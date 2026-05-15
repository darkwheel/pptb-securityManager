/// <reference types="@pptb/types" />

/**
 * Security Manager Tool for Power Platform Tool Box
 * 
 * This tool helps administrators check and manage user security permissions
 * in Dataverse environments.
 */

// Global API references
const toolbox = window.toolboxAPI;
const dataverse = window.dataverseAPI;

// Application state
let currentConnection: ToolBoxAPI.DataverseConnection | null = null;
let selectedUserId: string | null = null;
let hasRoleWritePermission: boolean = false;
let hasTeamWritePermission: boolean = false;
let searchDebounceTimer: ReturnType<typeof setTimeout> | null = null;

/**
 * Initialize the application
 */
async function initialize() {
    console.log('Security Manager Tool initialized');

    try {
        // Check if we have a connection
        currentConnection = await toolbox.connections.getActiveConnection();

        if (currentConnection) {
            console.log('Connected to:', currentConnection.url);

            // Check permissions
            await checkPermissions();

            await toolbox.utils.showNotification({
                title: 'Connected',
                body: 'Connected to Dataverse environment',
                type: 'success',
                duration: 3000
            });
        } else {
            console.log('No connection available');
            await toolbox.utils.showNotification({
                title: 'No Connection',
                body: 'Please connect to a Dataverse environment',
                type: 'warning',
                duration: 3000
            });
        }

        // Setup event handlers
        setupEventHandlers();

    } catch (error) {
        console.error('Initialization error:', error);
        await toolbox.utils.showNotification({
            title: 'Error',
            body: 'Failed to initialize: ' + (error as Error).message,
            type: 'error',
            duration: 3000
        });
        return;
    }
}

/**
 * Check if current user has write permissions for roles and teams
 */
async function checkPermissions() {
    const permissionStatus = document.getElementById('permission-status');
    const searchContainer = document.querySelector('.search-container') as HTMLElement;

    // Hide search bar initially
    if (searchContainer) searchContainer.style.display = 'none';

    if (!permissionStatus) return;

    try {
        permissionStatus.innerHTML = '<div class="permission-info">Checking permissions...</div>';

        // Get current user info
        const whoAmIResult = await dataverse.execute({
            operationName: 'WhoAmI',
            operationType: 'function'
        });

        const userId = whoAmIResult.UserId as string;

        // Get user details
        const userFetchXml = `
<fetch top="1">
    <entity name="systemuser">
        <attribute name="fullname" />
        <filter>
            <condition attribute="systemuserid" operator="eq" value="${userId}" />
        </filter>
    </entity>
</fetch>`;

        const userResult = await dataverse.fetchXmlQuery(userFetchXml);
        const userName = (userResult.value[0]?.fullname as string) || 'Unknown User';

        // Check role permissions (both read and write)
        const roleReadPermission = await checkEntityReadPermission('role');
        const roleWritePermission = await checkEntityWritePermission('role');
        hasRoleWritePermission = roleWritePermission;

        // Check team permissions (both read and write)
        const teamReadPermission = await checkEntityReadPermission('team');
        const teamWritePermission = await checkEntityWritePermission('team');
        hasTeamWritePermission = teamWritePermission;

        // Update UI with colored circles
        permissionStatus.innerHTML = `
            <div class="permission-info">
                <div class="current-user"><strong>Current user:</strong> ${escapeHtml(userName)}</div>
                <div class="permission-group">
                    <strong>Security Roles:</strong>
                    <span class="permission-indicator">
                        <span class="circle ${roleReadPermission ? 'green' : 'red'}" title="${roleReadPermission ? 'Read access granted' : 'No read access'}"></span> Read
                    </span>
                    <span class="permission-indicator">
                        <span class="circle ${roleWritePermission ? 'green' : 'red'}" title="${roleWritePermission ? 'Write access granted' : 'No write access'}"></span> Write
                    </span>
                </div>
                <div class="permission-group">
                    <strong>Teams:</strong>
                    <span class="permission-indicator">
                        <span class="circle ${teamReadPermission ? 'green' : 'red'}" title="${teamReadPermission ? 'Read access granted' : 'No read access'}"></span> Read
                    </span>
                    <span class="permission-indicator">
                        <span class="circle ${teamWritePermission ? 'green' : 'red'}" title="${teamWritePermission ? 'Write access granted' : 'No write access'}"></span> Write
                    </span>
                </div>
            </div>
        `;

        // Show search bar after permissions are loaded
        if (searchContainer) searchContainer.style.display = 'flex';

    } catch (error) {
        console.error('Error checking permissions:', error);
        permissionStatus.innerHTML = `
            <div class="permission-info warning">
                <strong>⚠️ Unable to verify permissions</strong>
            </div>
        `;
        // Show search bar even on error
        if (searchContainer) searchContainer.style.display = 'flex';
    }
}

/**
 * Check if user has read permission for a specific entity
 */
async function checkEntityReadPermission(entityName: string): Promise<boolean> {
    try {
        // Try to query the entity with a simple fetch
        const fetchXml = `
<fetch top="1">
    <entity name="${entityName}">
        <attribute name="${entityName}id" />
    </entity>
</fetch>`;

        await dataverse.fetchXmlQuery(fetchXml);
        return true;
    } catch (error) {
        console.error(`No read permission for ${entityName}:`, error);
        return false;
    }
}

/**
 * Check if user has write permission for a specific entity
 */
async function checkEntityWritePermission(entityName: string): Promise<boolean> {
    try {
        // Try to get entity metadata which requires read access
        await dataverse.getEntityMetadata(entityName, true, ['LogicalName']);

        // For write permission, we check if user has necessary privileges
        // by querying the user's privileges via WhoAmI and privilege check
        const whoAmIResult = await dataverse.execute({
            operationName: 'WhoAmI',
            operationType: 'function'
        });

        const userId = whoAmIResult.UserId as string;

        // Query user's security roles to determine write access
        // If user has System Administrator role or specific privileges, they can write
        const rolesFetchXml = `
<fetch top="1">
    <entity name="role">
        <attribute name="name" />
        <link-entity name="systemuserroles" from="roleid" to="roleid">
            <filter>
                <condition attribute="systemuserid" operator="eq" value="${userId}" />
            </filter>
        </link-entity>
        <filter type="or">
            <condition attribute="name" operator="eq" value="System Administrator" />
            <condition attribute="name" operator="like" value="%Admin%" />
        </filter>
    </entity>
</fetch>`;

        const rolesResult = await dataverse.fetchXmlQuery(rolesFetchXml);

        // If user has admin role, they have write permission
        if (rolesResult.value.length > 0) {
            return true;
        }

        // For non-admin users, we assume read-only unless they have specific privileges
        // A more sophisticated check would query privilege tables, but that's complex
        // For now, we'll return false for non-admins and let operations fail gracefully
        return false;

    } catch (error) {
        console.error(`Error checking write permission for ${entityName}:`, error);
        return false;
    }
}

/**
 * Setup event handlers for search
 */
function setupEventHandlers() {
    const searchBtn = document.getElementById('search-btn');
    const searchInput = document.getElementById('user-search-input') as HTMLInputElement;

    searchBtn?.addEventListener('click', performSearch);

    // Allow Enter key to trigger search
    searchInput?.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            performSearch();
        }
    });
}

/**
 * Perform user search
 */
async function performSearch() {
    const searchBtn = document.getElementById('search-btn') as HTMLButtonElement | null;
    const searchInput = document.getElementById('user-search-input') as HTMLInputElement | null;
    const statusDiv = document.getElementById('search-status');
    const resultsDiv = document.getElementById('user-results');
    const resultsSection = document.getElementById('results-section');

    const searchTerm = searchInput?.value.trim() ?? '';

    try {
        // Disable button during search
        if (searchBtn) searchBtn.disabled = true;
        if (statusDiv) {
            statusDiv.className = 'search-status info';
            statusDiv.textContent = searchTerm ? 'Searching...' : 'Searching...';
        }

        // Build FetchXML query to search users
        // Search across: domainname, fullname, firstname, lastname
        const fetchXml = `
<fetch>
    <entity name="systemuser">
        <attribute name="systemuserid" />
        <attribute name="fullname" />
        <attribute name="domainname" />
        <attribute name="firstname" />
        <attribute name="lastname" />
        <attribute name="internalemailaddress" />
        <attribute name="isdisabled" />
        <attribute name="title" />
        <attribute name="businessunitid" />
        <link-entity name="businessunit" from="businessunitid" to="businessunitid" alias="businessunit">
            <attribute name="name" />
            <attribute name="businessunitid" />
        </link-entity>
        <filter type="or">
            <condition attribute="domainname" operator="like" value="%${searchTerm}%" />
            <condition attribute="fullname" operator="like" value="%${searchTerm}%" />
            <condition attribute="firstname" operator="like" value="%${searchTerm}%" />
            <condition attribute="lastname" operator="like" value="%${searchTerm}%" />
        </filter>
        <order attribute="fullname" />
    </entity>
</fetch>`;

        const result = await dataverse.fetchXmlQuery(fetchXml);

        // Display results
        if (resultsDiv && resultsSection) {
            if (result.value.length === 0) {
                resultsSection.style.display = 'block';
                resultsDiv.innerHTML = '<div class="no-results">No users found matching your search criteria</div>';
                if (statusDiv) {
                    statusDiv.className = 'search-status info';
                    statusDiv.textContent = 'No results found';
                }
            } else {
                resultsSection.style.display = 'block';
                // Sort users by name, then by status (enabled before disabled)
                const sortedUsers = [...result.value].sort((a: any, b: any) => {
                    const nameA = (a.fullname || 'N/A').toLowerCase();
                    const nameB = (b.fullname || 'N/A').toLowerCase();
                    const nameCompare = nameA.localeCompare(nameB);
                    if (nameCompare !== 0) return nameCompare;
                    // Sort by status: enabled (false) before disabled (true)
                    return (a.isdisabled ? 1 : 0) - (b.isdisabled ? 1 : 0);
                });

                resultsDiv.innerHTML = sortedUsers.map((user: any) => `
                    <div class="user-card ${user.isdisabled ? 'disabled' : 'enabled'}" data-userid="${user.systemuserid}">
                        <div class="user-header">
                            <div class="user-name" title="${escapeHtml(user.fullname || 'N/A')}">${escapeHtml(user.fullname || 'N/A')}</div>
                            ${user['businessunit.name'] ? `<span class="business-unit-tag">${escapeHtml(user['businessunit.name'])}</span>` : ''}
                        </div>
                        <div class="user-detail">
                            <div class="user-detail-value" title="${escapeHtml(user.internalemailaddress || 'N/A')}">${escapeHtml(user.internalemailaddress || 'N/A')}</div>
                        </div>
                    </div>
                `).join('');

                // Add click handlers to user cards
                document.querySelectorAll('.user-card').forEach(card => {
                    card.addEventListener('click', () => {
                        const userId = (card as HTMLElement).getAttribute('data-userid');
                        if (userId) {
                            selectUser(userId, result.value.find((u: any) => u.systemuserid === userId));
                        }
                    });
                });

                if (statusDiv) {
                    statusDiv.className = 'search-status success';
                    statusDiv.textContent = `Found ${result.value.length} user(s)`;
                }
            }
        }

        await toolbox.utils.showNotification({
            title: 'Search Complete',
            body: `Found ${result.value.length} user(s)`,
            type: 'success',
            duration: 3000
        });

    } catch (error) {
        console.error('Search error:', error);
        if (statusDiv) {
            statusDiv.className = 'search-status error';
            statusDiv.textContent = `Error: ${(error as Error).message}`;
        }
        await toolbox.utils.showNotification({
            title: 'Search Failed',
            body: (error as Error).message,
            type: 'error',
            duration: 3000
        });
    } finally {
        if (searchBtn) searchBtn.disabled = false;
    }
}

/**
 * Select a user and display their details
 */
async function selectUser(userId: string, userData: any) {
    selectedUserId = userId;

    // Update selected state
    document.querySelectorAll('.user-card').forEach(card => {
        card.classList.remove('selected');
        if ((card as HTMLElement).getAttribute('data-userid') === userId) {
            card.classList.add('selected');
        }
    });

    const detailsPanel = document.getElementById('user-details-panel');
    if (!detailsPanel) return;

    // Clear the sticky header while loading
    const stickyHeaderEl = document.getElementById('user-sticky-header');
    if (stickyHeaderEl) stickyHeaderEl.innerHTML = '';

    // Show loading state
    detailsPanel.innerHTML = '<div class="loading-indicator">Loading user details</div>';

    try {
        // Fetch user roles, teams, team-derived roles, and all available roles in parallel
        console.log('User data:', userData);
        console.log('User business unit ID:', userData.businessunitid);
        console.log('User business unit object:', userData['businessunit.businessunitid']);

        // Extract business unit ID - it might be in different properties depending on how it was fetched
        const buId = userData.businessunitid || userData['businessunit.businessunitid'];
        console.log('Extracted BU ID:', buId);

        const [userRoles, userTeams, teamRoles, allAvailableRoles, allAvailableTeams] = await Promise.all([
            fetchUserRoles(userId),
            fetchUserTeams(userId),
            fetchTeamRolesForUser(userId),
            fetchAllAvailableRoles(buId || ''),
            fetchAllAvailableTeams(buId || '')
        ]);

        // Build combined roles list (direct + team)
        const combinedRoles = buildCombinedRoles(userRoles, teamRoles);

        // Display all information
        displayUserDetails(userData, userRoles, userTeams, combinedRoles, allAvailableRoles, allAvailableTeams);

        // Setup checkbox listeners and list filters after rendering
        setupCheckboxListeners();
        setupListFilters();

    } catch (error) {
        console.error('Error loading user details:', error);
        detailsPanel.innerHTML = `<div class="empty-state"><p>Error loading user details: ${(error as Error).message}</p></div>`;
        const stickyHeaderEl = document.getElementById('user-sticky-header');
        if (stickyHeaderEl) stickyHeaderEl.innerHTML = '';
    }
}

/**
 * Fetch user's security roles
 */
async function fetchUserRoles(userId: string): Promise<any[]> {
    const fetchXml = `
<fetch>
    <entity name="role">
        <attribute name="name" />
        <attribute name="roleid" />
        <attribute name="businessunitid" />
        <link-entity name="systemuserroles" from="roleid" to="roleid" alias="sur" link-type="inner">
            <filter>
                <condition attribute="systemuserid" operator="eq" value="${userId}" />
            </filter>
        </link-entity>
    </entity>
</fetch>`;

    const result = await dataverse.fetchXmlQuery(fetchXml);
    return result.value;
}

/**
 * Fetch all available roles in the system for a specific business unit
 */
async function fetchAllAvailableRoles(businessUnitId: string): Promise<any[]> {
    console.log('Fetching roles for business unit:', businessUnitId);

    // First, get the parent business unit chain
    const parentBuIds = await getParentBusinessUnitChain(businessUnitId);
    console.log('Business unit hierarchy:', [businessUnitId, ...parentBuIds]);

    const fetchXml = `
<fetch>
    <entity name="role">
        <attribute name="name" />
        <attribute name="roleid" />
        <attribute name="businessunitid" />
        <link-entity name="businessunit" from="businessunitid" to="businessunitid" alias="bu">
            <attribute name="name" />
        </link-entity>
    </entity>
</fetch>`;

    const result = await dataverse.fetchXmlQuery(fetchXml);
    console.log('Total roles from system:', result.value.length);

    // Filter roles to include user's BU and all parent BUs
    const allowedBuIds = new Set([businessUnitId, ...parentBuIds]);
    const filteredRoles = result.value.filter((role: any) =>
        allowedBuIds.has(role['_businessunitid_value'])
    );
    console.log('Roles from user BU and parent BUs:', filteredRoles.length);

    // Deduplicate by role name, prioritizing user's BU over parent BUs
    const rolesByName = new Map<string, any>();

    // Sort by BU priority: user's BU first, then parents in order
    const sortedRoles = filteredRoles.sort((a, b) => {
        const aBuId = a['_businessunitid_value'] as string;
        const bBuId = b['_businessunitid_value'] as string;

        if (aBuId === businessUnitId) return -1;
        if (bBuId === businessUnitId) return 1;

        const aIndex = parentBuIds.indexOf(aBuId);
        const bIndex = parentBuIds.indexOf(bBuId);
        return aIndex - bIndex;
    });

    // Keep only first occurrence of each role name (which will be from the closest BU)
    // Also mark if role is from a parent BU
    sortedRoles.forEach(role => {
        const roleName = role['name'] as string;
        if (!rolesByName.has(roleName)) {
            // Add flag indicating if this role is from a parent BU
            role.isFromParentBU = role['_businessunitid_value'] !== businessUnitId;
            rolesByName.set(roleName, role);
        }
    });

    const deduplicatedRoles = Array.from(rolesByName.values());
    console.log('Deduplicated roles:', deduplicatedRoles.length);

    return deduplicatedRoles;
}

/**
 * Get the parent business unit chain for a given business unit
 */
async function getParentBusinessUnitChain(businessUnitId: string): Promise<string[]> {
    const parentIds: string[] = [];
    let currentBuId: string | null = businessUnitId;

    // Walk up the parent chain (max 10 levels to prevent infinite loops)
    for (let i = 0; i < 10 && currentBuId; i++) {
        const fetchXml = `
<fetch top="1">
    <entity name="businessunit">
        <attribute name="parentbusinessunitid" />
        <filter>
            <condition attribute="businessunitid" operator="eq" value="${currentBuId}" />
        </filter>
    </entity>
</fetch>`;

        try {
            const result = await dataverse.fetchXmlQuery(fetchXml);
            if (result.value.length > 0) {
                const parentBuId = result.value[0]['_parentbusinessunitid_value'] as string | undefined;
                if (parentBuId && parentBuId !== currentBuId) {
                    parentIds.push(parentBuId);
                    currentBuId = parentBuId;
                } else {
                    // Reached root BU (no parent)
                    break;
                }
            } else {
                break;
            }
        } catch (error) {
            console.error('Error fetching parent BU:', error);
            break;
        }
    }

    return parentIds;
}

/**
 * Fetch user's team memberships
 */
async function fetchUserTeams(userId: string): Promise<any[]> {
    const fetchXml = `
<fetch>
    <entity name="teammembership">
        <attribute name="teammembershipid" />
        <filter>
            <condition attribute="systemuserid" operator="eq" value="${userId}" />
        </filter>
        <link-entity name="team" from="teamid" to="teamid" alias="team">
            <attribute name="name" />
            <attribute name="teamid" />
            <attribute name="businessunitid" />
        </link-entity>
    </entity>
</fetch>`;

    const result = await dataverse.fetchXmlQuery(fetchXml);
    return result.value;
}

/**
 * Fetch all available teams for a specific business unit
 */
async function fetchAllAvailableTeams(businessUnitId: string): Promise<any[]> {
    console.log('Fetching teams for business unit:', businessUnitId);

    const fetchXml = `
<fetch>
    <entity name="team">
        <attribute name="name" />
        <attribute name="teamid" />
        <attribute name="businessunitid" />
    </entity>
</fetch>`;

    const result = await dataverse.fetchXmlQuery(fetchXml);
    console.log('Total teams from system:', result.value.length);

    // Filter teams by business unit on client side
    const filteredTeams = result.value.filter((team: any) => team['_businessunitid_value'] === businessUnitId);
    console.log('Teams filtered for BU:', filteredTeams.length);
    console.log('Filtered teams:', filteredTeams);

    return filteredTeams;
}

/**
 * Fetch team-derived roles for the user (roles assigned via teams)
 */
async function fetchTeamRolesForUser(userId: string): Promise<any[]> {
    const fetchXml = `
<fetch distinct="true">
  <entity name="role">
    <attribute name="name" />
    <attribute name="businessunitid" />
    <attribute name="roleid" />
    <link-entity name="teamroles" from="roleid" to="roleid" intersect="true">
      <link-entity name="teammembership" from="teamid" to="teamid" intersect="true">
        <attribute name="teamid" />
        <link-entity name="team" from="teamid" to="teamid" alias="team">
          <attribute name="name" />
          <attribute name="teamid" />
        </link-entity>
        <link-entity name="systemuser" from="systemuserid" to="systemuserid" alias="user">
          <attribute name="systemuserid" />
          <filter>
            <condition attribute="systemuserid" operator="eq" value="${userId}" />
          </filter>
        </link-entity>
      </link-entity>
    </link-entity>
  </entity>
</fetch>`;

    const result = await dataverse.fetchXmlQuery(fetchXml);
    return result.value;
}

/**
 * Build combined roles list with source information
 */
function buildCombinedRoles(userRoles: any[], teamRoles: any[]) {
    const combinedMap: { [roleId: string]: { roleName: string, sources: { type: string, name?: string }[] } } = {};

    // Add user roles
    userRoles.forEach(ur => {
        const roleId = ur['roleid'] || ur['role.roleid'];
        const roleName = ur['name'] || ur['role.name'];
        if (!combinedMap[roleId]) {
            combinedMap[roleId] = { roleName, sources: [] };
        }
        combinedMap[roleId].sources.push({ type: 'user' });
    });

    // Add team roles (with team names)
    teamRoles.forEach(tr => {
        const roleId = tr['roleid'] || tr['role.roleid'];
        const roleName = tr['name'] || tr['role.name'];
        const teamName = tr['team.name'] || tr['team.teamid'];
        if (!combinedMap[roleId]) {
            combinedMap[roleId] = { roleName, sources: [] };
        }
        combinedMap[roleId].sources.push({ type: 'team', name: teamName });
    });

    // Convert to array
    return Object.entries(combinedMap).map(([roleId, data]) => ({
        roleId,
        roleName: data.roleName,
        sources: data.sources
    }));
}

/**
 * Display user details in the right panel
 */
function displayUserDetails(userData: any, userRoles: any[], userTeams: any[], combinedRoles: any[], allAvailableRoles: any[], allAvailableTeams: any[]) {
    const detailsPanel = document.getElementById('user-details-panel');
    if (!detailsPanel) return;

    // Get assigned role IDs - normalize property names
    const assignedRoleIds = new Set(userRoles.map(r => {
        const roleId = r['roleid'] || r['role.roleid'];
        console.log('Assigned role ID:', roleId, 'from object:', r);
        return roleId;
    }));

    // Get assigned team IDs
    const assignedTeamIds = new Set(userTeams.map(t => t['team.teamid'] || t['teamid']));

    // Get available teams (not assigned)
    const availableTeams = allAvailableTeams.filter(t => !assignedTeamIds.has(t['teamid']));

    console.log('All available roles count:', allAvailableRoles.length);
    console.log('All available roles sample:', allAvailableRoles.slice(0, 2));
    console.log('Assigned role IDs:', Array.from(assignedRoleIds));

    // Get available roles (not assigned)
    const availableRoles = allAvailableRoles.filter(r => {
        const roleId = r['roleid'];
        const isAssigned = assignedRoleIds.has(roleId);
        console.log('Checking role:', r.name, 'ID:', roleId, 'Is assigned:', isAssigned);
        return !isAssigned;
    });

    // Render the sticky header into the full-width element above the split-view
    const stickyHeaderEl = document.getElementById('user-sticky-header');
    if (stickyHeaderEl) {
        stickyHeaderEl.innerHTML = `
            <div class="user-details-header">
                <div class="sticky-panel-spacer"></div>
                <div class="sticky-panel-content">
                    <div>
                        <div class="user-details-title">${escapeHtml(userData.fullname || 'N/A')}</div>
                        <div style="display: flex; align-items: center; gap: 8px; margin-top: 5px;">
                            <span style="color: var(--text-secondary);">${escapeHtml(userData.internalemailaddress || 'N/A')}</span>
                            ${userData['businessunit.name'] ? `<span class="business-unit-tag ${userData.isdisabled ? 'disabled' : 'enabled'}">${escapeHtml(userData['businessunit.name'])}</span>` : ''}
                        </div>
                    </div>
                    <div class="user-status ${userData.isdisabled ? 'disabled' : 'enabled'}">
                        ${userData.isdisabled ? 'Disabled' : 'Enabled'}
                    </div>
                </div>
            </div>
        `;
    }

    detailsPanel.innerHTML = `
        <div class="details-section">
            <h3 class="collapsible-header" data-section="user-roles">
                <span class="collapse-icon">▼</span> 👤 User Roles
            </h3>
            <div class="role-split-view collapsible-content" id="user-roles-content">
                <div class="role-section">
                    <div class="role-header-with-button">
                        <h4>Assigned Roles (${userRoles.length})</h4>
                        <button class="btn btn-danger btn-sm" id="remove-roles-btn" disabled ${!hasRoleWritePermission ? 'style="display:none;"' : ''}>Remove Selected</button>
                    </div>
                    <input type="text" class="list-filter-input" placeholder="Filter assigned roles..." data-filter-section="assigned-roles" />
                    ${userRoles.length > 0 ? `
                        <table class="roles-table">
                            <thead>
                                <tr>
                                    <th style="width: 32px;"></th>
                                    <th>Role Name</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${[...userRoles].sort((a, b) => {
        const nameA = (a['name'] || a['role.name'] || 'N/A').toLowerCase();
        const nameB = (b['name'] || b['role.name'] || 'N/A').toLowerCase();
        return nameA.localeCompare(nameB);
    }).map(role => {
        const roleId = role['roleid'] || role['role.roleid'];
        return `
                                    <tr data-roleid="${roleId}">
                                        <td class="checkbox-cell"><input type="checkbox" class="assigned-role-checkbox"></td>
                                        <td>${escapeHtml(role['name'] || role['role.name'] || 'N/A')}</td>
                                    </tr>
                                `;
    }).join('')}
                            </tbody>
                        </table>
                    ` : '<div class="empty-message">No assigned roles</div>'}

                </div>

                <div class="role-section">
                    <div class="role-header-with-button">
                        <h4>Available Roles (${availableRoles.length})</h4>
                        <button class="btn btn-primary btn-sm" id="add-roles-btn" disabled ${!hasRoleWritePermission ? 'style="display:none;"' : ''}>Add Selected</button>
                    </div>
                    <input type="text" class="list-filter-input" placeholder="Filter available roles..." data-filter-section="available-roles" />
                    ${availableRoles.length > 0 ? `
                        <table class="roles-table">
                            <thead>
                                <tr>
                                    <th style="width: 32px;"></th>
                                    <th>Role Name</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${[...availableRoles].sort((a, b) => {
        const nameA = (a['name'] || 'N/A').toLowerCase();
        const nameB = (b['name'] || 'N/A').toLowerCase();
        return nameA.localeCompare(nameB);
    }).map(role => {
        const buName = role['bu.name'];
        const isFromParentBU = role.isFromParentBU;
        return `
                                    <tr data-roleid="${role['roleid']}">
                                        <td class="checkbox-cell"><input type="checkbox" class="available-role-checkbox"></td>
                                        <td>
                                            ${escapeHtml(role['name'] || 'N/A')}
                                            ${isFromParentBU && buName ? `<span class="business-unit-tag parent-bu" style="margin-left: 8px;" title="From parent business unit">${escapeHtml(buName)}</span>` : ''}
                                        </td>
                                    </tr>
                                `;
    }).join('')}
                            </tbody>
                        </table>
                    ` : '<div class="empty-message">All available roles assigned</div>'}
                </div>
            </div>
        </div>

        <div class="details-section">
            <h3 class="collapsible-header" data-section="team-memberships">
                <span class="collapse-icon">▼</span> 👥 Team Memberships
            </h3>
            <div class="role-split-view collapsible-content" id="team-memberships-content">
                    <div class="role-section">
                        <div class="role-header-with-button">
                            <h4>Assigned Teams (${userTeams.length})</h4>
                            <button class="btn btn-danger btn-sm" id="remove-teams-btn" disabled ${!hasTeamWritePermission ? 'style="display:none;"' : ''}>Remove Selected</button>
                        </div>
                        <input type="text" class="list-filter-input" placeholder="Filter assigned teams..." data-filter-section="assigned-teams" />
                        ${userTeams.length > 0 ? `
                            <table class="roles-table">
                                <thead>
                                    <tr>
                                        <th style="width: 32px;"></th>
                                        <th>Team Name</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${[...userTeams].sort((a, b) => {
        const nameA = (a['team.name'] || 'N/A').toLowerCase();
        const nameB = (b['team.name'] || 'N/A').toLowerCase();
        return nameA.localeCompare(nameB);
    }).map(team => {
        const teamId = team['team.teamid'] || team['teamid'];
        return `
                                        <tr data-teamid="${teamId}">
                                            <td class="checkbox-cell"><input type="checkbox" class="assigned-team-checkbox"></td>
                                            <td>${escapeHtml(team['team.name'] || 'N/A')}</td>
                                        </tr>
                                    `;
    }).join('')}
                                </tbody>
                            </table>
                        ` : '<div class="empty-message">No team memberships</div>'}
                    </div>

                    <div class="role-section">
                        <div class="role-header-with-button">
                            <h4>Available Teams (${availableTeams.length})</h4>
                            <button class="btn btn-primary btn-sm" id="add-teams-btn" disabled ${!hasTeamWritePermission ? 'style="display:none;"' : ''}>Add Selected</button>
                        </div>
                        <input type="text" class="list-filter-input" placeholder="Filter available teams..." data-filter-section="available-teams" />
                        ${availableTeams.length > 0 ? `
                            <table class="roles-table">
                                <thead>
                                    <tr>
                                        <th style="width: 32px;"></th>
                                        <th>Team Name</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${[...availableTeams].sort((a, b) => {
        const nameA = (a['name'] || 'N/A').toLowerCase();
        const nameB = (b['name'] || 'N/A').toLowerCase();
        return nameA.localeCompare(nameB);
    }).map(team => `
                                        <tr data-teamid="${team['teamid']}">
                                            <td class="checkbox-cell"><input type="checkbox" class="available-team-checkbox"></td>
                                            <td>${escapeHtml(team['name'] || 'N/A')}</td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        ` : '<div class="empty-message">All available teams assigned</div>'}
                    </div>
                </div>
        </div>

        <div class="details-section">
            <h3 class="collapsible-header" data-section="combined-roles">
                <span class="collapse-icon">▼</span> 🔐 All Roles (Combined View)
            </h3>
            <div class="collapsible-content" id="combined-roles-content">
            ${combinedRoles.length > 0 ? `
                <table class="roles-table">
                    <thead>
                        <tr>
                            <th>Role Name</th>
                            <th>Source</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${[...combinedRoles].sort((a, b) => {
        const nameA = (a.roleName || 'N/A').toLowerCase();
        const nameB = (b.roleName || 'N/A').toLowerCase();
        return nameA.localeCompare(nameB);
    }).map(role => `
                            <tr>
                                <td>${escapeHtml(role.roleName)}</td>
                                <td>
                                    ${role.sources.map((source: any) =>
        source.type === 'user'
            ? '<span class="role-source-user">Direct (User)</span>'
            : `<span class="role-source-team">Team: ${escapeHtml(source.name)}</span>`
    ).join(' ')}
                                </td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            ` : '<div class="empty-message">No roles found</div>'}
            </div>
        </div>
    `;

    // Setup collapsible sections
    setupCollapsibleSections();

    // Toggle shadow on sticky header when it becomes stuck\n    const sentinel = document.getElementById('sticky-sentinel');\n    if (sentinel && stickyHeaderEl) {\n        const observer = new IntersectionObserver(\n            ([entry]) => {\n                stickyHeaderEl.classList.toggle('is-stuck', !entry.isIntersecting);\n            },\n            { threshold: [1] }\n        );\n        observer.observe(sentinel);\n    }
}

/**
 * Setup checkbox listeners for role and team selection
 */
function setupCheckboxListeners() {
    const assignedRoleCheckboxes = document.querySelectorAll('.assigned-role-checkbox') as NodeListOf<HTMLInputElement>;
    const availableRoleCheckboxes = document.querySelectorAll('.available-role-checkbox') as NodeListOf<HTMLInputElement>;
    const assignedTeamCheckboxes = document.querySelectorAll('.assigned-team-checkbox') as NodeListOf<HTMLInputElement>;
    const availableTeamCheckboxes = document.querySelectorAll('.available-team-checkbox') as NodeListOf<HTMLInputElement>;

    const allCheckboxes = document.querySelectorAll('.assigned-role-checkbox, .available-role-checkbox, .assigned-team-checkbox, .available-team-checkbox') as NodeListOf<HTMLInputElement>;

    const removeRolesBtn = document.getElementById('remove-roles-btn') as HTMLButtonElement | null;
    const addRolesBtn = document.getElementById('add-roles-btn') as HTMLButtonElement | null;
    const removeTeamsBtn = document.getElementById('remove-teams-btn') as HTMLButtonElement | null;
    const addTeamsBtn = document.getElementById('add-teams-btn') as HTMLButtonElement | null;

    const updateButtonStates = () => {
        const hasAssignedRolesSelected = Array.from(assignedRoleCheckboxes).some((cb) => cb.checked);
        const hasAvailableRolesSelected = Array.from(availableRoleCheckboxes).some((cb) => cb.checked);
        const hasAssignedTeamsSelected = Array.from(assignedTeamCheckboxes).some((cb) => cb.checked);
        const hasAvailableTeamsSelected = Array.from(availableTeamCheckboxes).some((cb) => cb.checked);

        if (removeRolesBtn) removeRolesBtn.disabled = !hasAssignedRolesSelected;
        if (addRolesBtn) addRolesBtn.disabled = !hasAvailableRolesSelected;
        if (removeTeamsBtn) removeTeamsBtn.disabled = !hasAssignedTeamsSelected;
        if (addTeamsBtn) addTeamsBtn.disabled = !hasAvailableTeamsSelected;
    };

    allCheckboxes.forEach(checkbox => {
        checkbox.addEventListener('change', function (this: HTMLInputElement) {
            const row = (this.closest('tr') as HTMLTableRowElement);
            if (row) {
                if (this.checked) {
                    row.classList.add('checked-row');
                } else {
                    row.classList.remove('checked-row');
                }
            }
            updateButtonStates();
        });
    });

    // Set initial state
    updateButtonStates();

    // Setup button handlers
    if (removeRolesBtn) {
        removeRolesBtn.addEventListener('click', handleRemoveRoles);
    }

    if (addRolesBtn) {
        addRolesBtn.addEventListener('click', handleAddRoles);
    }

    if (removeTeamsBtn) {
        removeTeamsBtn.addEventListener('click', handleRemoveTeams);
    }

    if (addTeamsBtn) {
        addTeamsBtn.addEventListener('click', handleAddTeams);
    }
}

/**
 * Setup collapsible section handlers
 */
function setupCollapsibleSections() {
    const headers = document.querySelectorAll('.collapsible-header');

    headers.forEach(header => {
        header.addEventListener('click', function (this: HTMLElement) {
            const sectionName = this.getAttribute('data-section');
            const content = document.getElementById(`${sectionName}-content`);
            const icon = this.querySelector('.collapse-icon');

            if (content && icon) {
                const isCollapsed = content.classList.contains('collapsed');

                if (isCollapsed) {
                    content.classList.remove('collapsed');
                    icon.textContent = '▼';
                } else {
                    content.classList.add('collapsed');
                    icon.textContent = '▶';
                }
            }
        });
    });
}

/**
 * Setup filter inputs for the role and team lists.
 * Rows are only hidden – never removed – so checkbox state is preserved across filter changes.
 */
function setupListFilters() {
    const inputs = document.querySelectorAll<HTMLInputElement>('.list-filter-input');
    inputs.forEach(input => {
        input.addEventListener('input', function (this: HTMLInputElement) {
            const query = this.value.trim().toLowerCase();
            const section = this.closest('.role-section');
            if (!section) return;
            const rows = section.querySelectorAll<HTMLTableRowElement>('tbody tr');
            rows.forEach(row => {
                const text = row.textContent?.toLowerCase() ?? '';
                row.style.display = query === '' || text.includes(query) ? '' : 'none';
            });
        });
    });
}

/**
 * Handle removing selected roles from user
 */
async function handleRemoveRoles() {
    if (!selectedUserId) return;

    const checkedBoxes = document.querySelectorAll('.assigned-role-checkbox:checked');
    if (checkedBoxes.length === 0) {
        await toolbox.utils.showNotification({
            title: 'No Selection',
            body: 'Please select at least one role to remove',
            type: 'warning',
            duration: 3000
        });
        return;
    }

    const roleIds: string[] = [];
    checkedBoxes.forEach(checkbox => {
        const row = checkbox.closest('tr');
        const roleId = row?.getAttribute('data-roleid');
        if (roleId) roleIds.push(roleId);
    });

    const removeRolesBtn = document.getElementById('remove-roles-btn') as HTMLButtonElement | null;
    const originalText = removeRolesBtn?.textContent || '';

    try {
        // Disable button and show loading state
        if (removeRolesBtn) {
            removeRolesBtn.disabled = true;
            removeRolesBtn.textContent = `Removing ${roleIds.length} role(s)...`;
        }

        await toolbox.utils.showNotification({
            title: 'Removing Roles',
            body: `Removing ${roleIds.length} role(s)...`,
            type: 'info',
            duration: 2000
        });

        // Remove each role
        for (let i = 0; i < roleIds.length; i++) {
            if (removeRolesBtn) {
                removeRolesBtn.textContent = `Removing (${i + 1}/${roleIds.length})...`;
            }
            await disassociateUserRole(selectedUserId, roleIds[i]);
        }

        await toolbox.utils.showNotification({
            title: 'Success',
            body: `Successfully removed ${roleIds.length} role(s)`,
            type: 'success',
            duration: 3000
        });

        // Refresh user details
        const userData = await getUserData(selectedUserId);
        if (userData) {
            await selectUser(selectedUserId, userData);
        }
    } catch (error) {
        console.error('Error removing roles:', error);
        await toolbox.utils.showNotification({
            title: 'Error',
            body: 'Failed to remove roles: ' + (error as Error).message,
            type: 'error',
            duration: 5000
        });
    } finally {
        // Restore button state
        if (removeRolesBtn) {
            removeRolesBtn.textContent = originalText;
            removeRolesBtn.disabled = false;
        }
    }
}

/**
 * Handle adding selected roles to user
 */
async function handleAddRoles() {
    if (!selectedUserId) return;

    const checkedBoxes = document.querySelectorAll('.available-role-checkbox:checked');
    if (checkedBoxes.length === 0) {
        await toolbox.utils.showNotification({
            title: 'No Selection',
            body: 'Please select at least one role to add',
            type: 'warning',
            duration: 3000
        });
        return;
    }

    const roleIds: string[] = [];
    checkedBoxes.forEach(checkbox => {
        const row = checkbox.closest('tr');
        const roleId = row?.getAttribute('data-roleid');
        if (roleId) roleIds.push(roleId);
    });

    const addRolesBtn = document.getElementById('add-roles-btn') as HTMLButtonElement | null;
    const originalText = addRolesBtn?.textContent || '';

    try {
        // Disable button and show loading state
        if (addRolesBtn) {
            addRolesBtn.disabled = true;
            addRolesBtn.textContent = `Adding ${roleIds.length} role(s)...`;
        }

        await toolbox.utils.showNotification({
            title: 'Adding Roles',
            body: `Adding ${roleIds.length} role(s)...`,
            type: 'info',
            duration: 2000
        });

        // Add each role
        for (let i = 0; i < roleIds.length; i++) {
            if (addRolesBtn) {
                addRolesBtn.textContent = `Adding (${i + 1}/${roleIds.length})...`;
            }
            await associateUserRole(selectedUserId, roleIds[i]);
        }

        await toolbox.utils.showNotification({
            title: 'Success',
            body: `Successfully added ${roleIds.length} role(s)`,
            type: 'success',
            duration: 3000
        });

        // Refresh user details
        const userData = await getUserData(selectedUserId);
        if (userData) {
            await selectUser(selectedUserId, userData);
        }
    } catch (error) {
        console.error('Error adding roles:', error);
        await toolbox.utils.showNotification({
            title: 'Error',
            body: 'Failed to add roles: ' + (error as Error).message,
            type: 'error',
            duration: 5000
        });
    } finally {
        // Restore button state
        if (addRolesBtn) {
            addRolesBtn.textContent = originalText;
            addRolesBtn.disabled = false;
        }
    }
}

/**
 * Associate a role with a user
 */
async function associateUserRole(userId: string, roleId: string): Promise<void> {
    await dataverse.associate('systemuser', userId, 'systemuserroles_association', 'role', roleId);
}

/**
 * Disassociate a role from a user
 */
async function disassociateUserRole(userId: string, roleId: string): Promise<void> {
    await dataverse.disassociate('systemuser', userId, 'systemuserroles_association', roleId);
}

/**
 * Handle adding selected teams to user
 */
async function handleAddTeams() {
    if (!selectedUserId) return;

    const checkedBoxes = document.querySelectorAll('.available-team-checkbox:checked');
    if (checkedBoxes.length === 0) {
        await toolbox.utils.showNotification({
            title: 'No Selection',
            body: 'Please select at least one team to add',
            type: 'warning',
            duration: 3000
        });
        return;
    }

    const teamIds: string[] = [];
    checkedBoxes.forEach(checkbox => {
        const row = checkbox.closest('tr');
        const teamId = row?.getAttribute('data-teamid');
        if (teamId) teamIds.push(teamId);
    });

    const addTeamsBtn = document.getElementById('add-teams-btn') as HTMLButtonElement | null;
    const originalText = addTeamsBtn?.textContent || '';

    try {
        // Disable button and show loading state
        if (addTeamsBtn) {
            addTeamsBtn.disabled = true;
            addTeamsBtn.textContent = `Adding ${teamIds.length} team(s)...`;
        }

        await toolbox.utils.showNotification({
            title: 'Adding Teams',
            body: `Adding ${teamIds.length} team(s)...`,
            type: 'info',
            duration: 2000
        });

        // Add each team
        for (let i = 0; i < teamIds.length; i++) {
            if (addTeamsBtn) {
                addTeamsBtn.textContent = `Adding (${i + 1}/${teamIds.length})...`;
            }
            const teamId = teamIds[i];
            await addTeamToUser(selectedUserId, teamId);
        }

        await toolbox.utils.showNotification({
            title: 'Success',
            body: `Successfully added ${teamIds.length} team(s)`,
            type: 'success',
            duration: 3000
        });

        // Refresh user details
        const userData = await getUserData(selectedUserId);
        if (userData) {
            await selectUser(selectedUserId, userData);
        }
    } catch (error) {
        console.error('Error adding teams:', error);
        await toolbox.utils.showNotification({
            title: 'Error',
            body: 'Failed to add teams: ' + (error as Error).message,
            type: 'error',
            duration: 5000
        });
    } finally {
        // Restore button state
        if (addTeamsBtn) {
            addTeamsBtn.textContent = originalText;
            addTeamsBtn.disabled = false;
        }
    }
}

/**
 * Handle removing selected teams from user
 */
async function handleRemoveTeams() {
    if (!selectedUserId) return;

    const checkedBoxes = document.querySelectorAll('.assigned-team-checkbox:checked');
    if (checkedBoxes.length === 0) {
        await toolbox.utils.showNotification({
            title: 'No Selection',
            body: 'Please select at least one team to remove',
            type: 'warning',
            duration: 3000
        });
        return;
    }

    const teamIds: string[] = [];
    checkedBoxes.forEach(checkbox => {
        const row = checkbox.closest('tr');
        const teamId = row?.getAttribute('data-teamid');
        if (teamId) teamIds.push(teamId);
    });

    const removeTeamsBtn = document.getElementById('remove-teams-btn') as HTMLButtonElement | null;
    const originalText = removeTeamsBtn?.textContent || '';

    try {
        // Disable button and show loading state
        if (removeTeamsBtn) {
            removeTeamsBtn.disabled = true;
            removeTeamsBtn.textContent = `Removing ${teamIds.length} team(s)...`;
        }

        await toolbox.utils.showNotification({
            title: 'Removing Teams',
            body: `Removing ${teamIds.length} team(s)...`,
            type: 'info',
            duration: 2000
        });

        // Remove each team
        for (let i = 0; i < teamIds.length; i++) {
            if (removeTeamsBtn) {
                removeTeamsBtn.textContent = `Removing (${i + 1}/${teamIds.length})...`;
            }
            await removeTeamFromUser(selectedUserId, teamIds[i]);
        }

        await toolbox.utils.showNotification({
            title: 'Success',
            body: `Successfully removed ${teamIds.length} team(s)`,
            type: 'success',
            duration: 3000
        });

        // Refresh user details
        const userData = await getUserData(selectedUserId);
        if (userData) {
            await selectUser(selectedUserId, userData);
        }
    } catch (error) {
        console.error('Error removing teams:', error);
        await toolbox.utils.showNotification({
            title: 'Error',
            body: 'Failed to remove teams: ' + (error as Error).message,
            type: 'error',
            duration: 5000
        });
    } finally {
        // Restore button state
        if (removeTeamsBtn) {
            removeTeamsBtn.textContent = originalText;
            removeTeamsBtn.disabled = false;
        }
    }
}

/**
 * Add a team to a user (associate via teammembership)
 */
async function addTeamToUser(userId: string, teamId: string): Promise<void> {
    await dataverse.associate('systemuser', userId, 'teammembership_association', 'team', teamId);
}

/**
 * Remove a team from a user (disassociate via teammembership)
 */
async function removeTeamFromUser(userId: string, teamId: string): Promise<void> {
    await dataverse.disassociate('systemuser', userId, 'teammembership_association', teamId);
}

/**
 * Get user data by ID
 */
async function getUserData(userId: string): Promise<any> {
    const fetchXml = `
<fetch top="1">
    <entity name="systemuser">
        <attribute name="systemuserid" />
        <attribute name="fullname" />
        <attribute name="domainname" />
        <attribute name="internalemailaddress" />
        <attribute name="isdisabled" />
        <attribute name="businessunitid" />
        <link-entity name="businessunit" from="businessunitid" to="businessunitid" alias="businessunit">
            <attribute name="name" />
            <attribute name="businessunitid" />
        </link-entity>
        <filter>
            <condition attribute="systemuserid" operator="eq" value="${userId}" />
        </filter>
    </entity>
</fetch>`;

    const result = await dataverse.fetchXmlQuery(fetchXml);
    return result.value[0];
}

/**
 * Add a role to a user (create systemuserroles record)
 * TODO: Implement once PPTB API supports associate()
 */
async function addUserRole(userId: string, roleId: string): Promise<void> {
    // TODO: Implementation pending
}

/**
 * Remove a role from a user (delete systemuserroles record)
 * TODO: Implement once PPTB API supports disassociate()
 */
async function removeUserRole(userId: string, roleId: string): Promise<void> {
    // TODO: Implementation pending
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text: string): string {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initialize);
} else {
    initialize();
}
