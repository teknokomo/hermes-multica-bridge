(function () {
  'use strict'

  const SDK = window.__HERMES_PLUGIN_SDK__
  const registry = window.__HERMES_PLUGINS__
  if (!SDK || !registry) return

  const React = SDK.React

  function BridgeDashboardPage() {
    const [status, setStatus] = React.useState(null)
    const [error, setError] = React.useState('')

    const refresh = React.useCallback(function () {
      setError('')
      return SDK.fetchJSON('/api/plugins/hermes-multica-bridge/status')
        .then(setStatus)
        .catch(function (err) {
          setError(err instanceof Error ? err.message : String(err))
        })
    }, [])

    React.useEffect(function () { void refresh() }, [refresh])

    const routes = status && Array.isArray(status.routes) ? status.routes : []
    const counts = status && status.counts ? status.counts : {}
    const enabledRoutes = routes.filter(function (route) { return route.enabled })
    const statusError = status && status.ok === false ? (status.message || status.error_code || 'Статус недоступен.') : ''
    return React.createElement('div', { className: 'hmb-dashboard' },
      React.createElement('h1', null, 'Hermes ↔ Multica Bridge'),
      error ? React.createElement('p', { role: 'alert' }, error) : null,
      statusError ? React.createElement('p', { role: 'alert' }, statusError) : null,
      React.createElement('dl', { className: 'hmb-dashboard-grid' },
        React.createElement('dt', null, 'Connections'), React.createElement('dd', null, status ? (counts.connections || 0) : '…'),
        React.createElement('dt', null, 'Workspaces'), React.createElement('dd', null, status ? (counts.workspaces || 0) : '…'),
        React.createElement('dt', null, 'Routes'), React.createElement('dd', null, status ? (counts.routes || 0) : '…'),
        React.createElement('dt', null, 'Активные Routes'), React.createElement('dd', null, status ? enabledRoutes.length : '…'),
        React.createElement('dt', null, 'Общая готовность'), React.createElement('dd', null, status ? (status.configured ? 'готово' : 'требует настройки') : 'проверяется…')
      ),
      routes.map(function (route) {
        const readiness = Array.isArray(route.readiness_errors) ? route.readiness_errors : []
        return React.createElement('section', { className: 'hmb-dashboard-route', key: route.route_id },
          React.createElement('strong', null, route.route_id),
          React.createElement('dl', { className: 'hmb-dashboard-grid' },
            React.createElement('dt', null, 'Состояние'), React.createElement('dd', null, route.tombstoned ? 'tombstone' : (route.enabled ? 'включён' : 'выключен')),
            React.createElement('dt', null, 'Тип'), React.createElement('dd', null, route.route_type || 'autopilot'),
            React.createElement('dt', null, 'Назначение'), React.createElement('dd', null, route.purpose || '—'),
            React.createElement('dt', null, 'Режим'), React.createElement('dd', null, route.security_mode || '—'),
            React.createElement('dt', null, 'Project ID'), React.createElement('dd', null, route.project_id || '—'),
            React.createElement('dt', null, 'Watcher'), React.createElement('dd', null, route.route_type === 'workspace' ? (route.watcher_ready ? 'готов' : 'недоступен') : '—'),
            React.createElement('dt', null, 'Исполнители'), React.createElement('dd', null, (route.assignees || []).map(function (item) { return (item.label || item.id) + ' (' + item.type + ')' + (item.default ? ' · default' : '') }).join(', ') || '—'),
            React.createElement('dt', null, 'Требовать исполнителя'), React.createElement('dd', null, route.route_type === 'workspace' ? (route.require_assignee ? 'да' : 'нет') : '—'),
            React.createElement('dt', null, 'Тестовый маршрут'), React.createElement('dd', null, route.route_type === 'workspace' ? (route.test ? 'да' : 'нет') : '—'),
            React.createElement('dt', null, 'Диагностика'), React.createElement('dd', null, (route.warnings || []).join(', ') || '—'),
            React.createElement('dt', null, 'Readiness'), React.createElement('dd', null, route.configured ? 'готов' : (readiness.join(', ') || 'требует настройки')),
            React.createElement('dt', null, 'Isolated socket'), React.createElement('dd', null, route.isolated_socket_path || '—')
          )
        )
      }),
      React.createElement('p', { className: 'hmb-dashboard-note' }, 'Секретные значения здесь не отображаются. Полная настройка доступна в Hermes Desktop и Settings → Plugins → Agent settings.'),
      React.createElement('button', { type: 'button', onClick: function () { void refresh() } }, 'Обновить')
    )
  }

  registry.register('hermes-multica-bridge', BridgeDashboardPage)
})()
