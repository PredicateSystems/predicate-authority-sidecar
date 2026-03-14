import { useState, useEffect } from 'react'

// Types for authorization events from SSE
interface AuthEvent {
  principal_id: string
  action: string
  resource: string
  result: 'ALLOW' | 'DENY'
  latency_us: number
  timestamp: number
}

// Token management
function getToken(): string | null {
  // First check sessionStorage
  const stored = sessionStorage.getItem('webui_token')
  if (stored) return stored

  // Then check URL query param
  const params = new URLSearchParams(window.location.search)
  const urlToken = params.get('token')
  if (urlToken) {
    // Store in sessionStorage and clean URL
    sessionStorage.setItem('webui_token', urlToken)
    window.history.replaceState({}, '', window.location.pathname)
    return urlToken
  }

  return null
}

// Format latency for display
function formatLatency(us: number): string {
  if (us < 1000) return `${us}μs`
  return `${(us / 1000).toFixed(1)}ms`
}

// Format timestamp for display
function formatTime(epoch: number): string {
  return new Date(epoch * 1000).toLocaleTimeString()
}

// Truncate long strings
function truncate(str: string, max: number): string {
  return str.length > max ? str.slice(0, max) + '...' : str
}

// Connection status component
function ConnectionStatus({ connected }: { connected: boolean }) {
  return (
    <div className="flex items-center gap-2">
      <div
        className={`w-2 h-2 rounded-full ${
          connected ? 'bg-accent-allow animate-pulse' : 'bg-accent-deny'
        }`}
      />
      <span className="text-sm text-text-secondary">
        {connected ? 'Connected' : 'Disconnected'}
      </span>
    </div>
  )
}

// Event log component
function EventLog({ events }: { events: AuthEvent[] }) {
  return (
    <div className="flex-1 overflow-auto">
      <table className="w-full text-sm">
        <thead className="sticky top-0 bg-bg-secondary">
          <tr className="text-left text-text-secondary border-b border-bg-card">
            <th className="px-3 py-2 w-20">Result</th>
            <th className="px-3 py-2">Principal</th>
            <th className="px-3 py-2">Action</th>
            <th className="px-3 py-2">Resource</th>
            <th className="px-3 py-2 w-20 text-right">Latency</th>
            <th className="px-3 py-2 w-24 text-right">Time</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event, i) => (
            <tr
              key={`${event.timestamp}-${i}`}
              className="border-b border-bg-card/50 hover:bg-bg-card/30"
            >
              <td className="px-3 py-2">
                <span
                  className={`font-bold ${
                    event.result === 'ALLOW'
                      ? 'text-accent-allow'
                      : 'text-accent-deny'
                  }`}
                >
                  {event.result}
                </span>
              </td>
              <td className="px-3 py-2 font-mono text-xs">
                {truncate(event.principal_id, 25)}
              </td>
              <td className="px-3 py-2 font-mono text-xs">
                {truncate(event.action, 25)}
              </td>
              <td className="px-3 py-2 font-mono text-xs text-text-secondary">
                {truncate(event.resource, 40)}
              </td>
              <td className="px-3 py-2 text-right text-accent-info">
                {formatLatency(event.latency_us)}
              </td>
              <td className="px-3 py-2 text-right text-text-secondary">
                {formatTime(event.timestamp)}
              </td>
            </tr>
          ))}
          {events.length === 0 && (
            <tr>
              <td colSpan={6} className="px-3 py-8 text-center text-text-secondary">
                Waiting for authorization events...
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}

// Policy viewer component
function PolicyViewer({ token }: { token: string }) {
  const [policy, setPolicy] = useState<string>('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetch(`/ui/api/policy/raw`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`)
        return res.text()
      })
      .then((text) => {
        setPolicy(text)
        setLoading(false)
      })
      .catch((err) => {
        setError(err.message)
        setLoading(false)
      })
  }, [token])

  if (loading) {
    return (
      <div className="p-4 text-text-secondary">Loading policy...</div>
    )
  }

  if (error) {
    return (
      <div className="p-4 text-accent-deny">
        Failed to load policy: {error}
      </div>
    )
  }

  return (
    <pre className="p-4 overflow-auto text-sm font-mono text-text-primary whitespace-pre">
      {policy}
    </pre>
  )
}

// Copy token button component
function CopyTokenButton({ token }: { token: string }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = () => {
    const url = `${window.location.origin}/ui/?token=${token}`
    navigator.clipboard.writeText(url).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  return (
    <button
      onClick={handleCopy}
      className="text-sm px-2 py-1 rounded bg-bg-card hover:bg-bg-card/80 text-text-secondary hover:text-text-primary transition-colors"
    >
      {copied ? 'Copied!' : 'Copy URL'}
    </button>
  )
}

// Stats component
function Stats({ events }: { events: AuthEvent[] }) {
  const allowed = events.filter((e) => e.result === 'ALLOW').length
  const denied = events.filter((e) => e.result === 'DENY').length
  const avgLatency =
    events.length > 0
      ? events.reduce((sum, e) => sum + e.latency_us, 0) / events.length
      : 0

  return (
    <div className="flex gap-6 text-sm">
      <div>
        <span className="text-text-secondary">Allowed: </span>
        <span className="text-accent-allow font-bold">{allowed}</span>
      </div>
      <div>
        <span className="text-text-secondary">Denied: </span>
        <span className="text-accent-deny font-bold">{denied}</span>
      </div>
      <div>
        <span className="text-text-secondary">Avg Latency: </span>
        <span className="text-accent-info font-bold">
          {formatLatency(Math.round(avgLatency))}
        </span>
      </div>
    </div>
  )
}

// Unauthorized view
function Unauthorized() {
  return (
    <div className="min-h-screen bg-bg-primary flex items-center justify-center">
      <div className="bg-bg-secondary rounded-lg p-8 max-w-md text-center">
        <h1 className="text-2xl font-bold text-text-primary mb-4">
          Unauthorized
        </h1>
        <p className="text-text-secondary mb-4">
          Access the Web UI via the URL printed in terminal when starting the
          sidecar with <code className="bg-bg-card px-2 py-1 rounded">--web-ui</code>
        </p>
        <p className="text-text-secondary text-sm">
          Example:{' '}
          <code className="bg-bg-card px-2 py-1 rounded text-accent-info">
            http://localhost:8787/ui/?token=abc123
          </code>
        </p>
      </div>
    </div>
  )
}

// Filter state
interface Filters {
  principal: string
  action: string
  result: 'all' | 'ALLOW' | 'DENY'
}

// Filter controls component
function FilterControls({
  filters,
  onChange,
}: {
  filters: Filters
  onChange: (filters: Filters) => void
}) {
  return (
    <div className="flex gap-3 items-center text-sm">
      <input
        type="text"
        placeholder="Filter principal..."
        value={filters.principal}
        onChange={(e) => onChange({ ...filters, principal: e.target.value })}
        className="bg-bg-card text-text-primary px-2 py-1 rounded border border-bg-card focus:border-accent-info outline-none w-32"
      />
      <input
        type="text"
        placeholder="Filter action..."
        value={filters.action}
        onChange={(e) => onChange({ ...filters, action: e.target.value })}
        className="bg-bg-card text-text-primary px-2 py-1 rounded border border-bg-card focus:border-accent-info outline-none w-32"
      />
      <select
        value={filters.result}
        onChange={(e) =>
          onChange({ ...filters, result: e.target.value as Filters['result'] })
        }
        className="bg-bg-card text-text-primary px-2 py-1 rounded border border-bg-card focus:border-accent-info outline-none"
      >
        <option value="all">All Results</option>
        <option value="ALLOW">ALLOW only</option>
        <option value="DENY">DENY only</option>
      </select>
      {(filters.principal || filters.action || filters.result !== 'all') && (
        <button
          onClick={() => onChange({ principal: '', action: '', result: 'all' })}
          className="text-text-secondary hover:text-text-primary"
        >
          Clear
        </button>
      )}
    </div>
  )
}

// Main App component
export default function App() {
  const [token] = useState<string | null>(getToken)
  const [events, setEvents] = useState<AuthEvent[]>([])
  const [connected, setConnected] = useState(false)
  const [filters, setFilters] = useState<Filters>({
    principal: '',
    action: '',
    result: 'all',
  })

  // Filter events based on current filters
  const filteredEvents = events.filter((event) => {
    if (filters.principal && !event.principal_id.toLowerCase().includes(filters.principal.toLowerCase())) {
      return false
    }
    if (filters.action && !event.action.toLowerCase().includes(filters.action.toLowerCase())) {
      return false
    }
    if (filters.result !== 'all' && event.result !== filters.result) {
      return false
    }
    return true
  })

  // SSE connection
  useEffect(() => {
    if (!token) return

    const eventSource = new EventSource(`/ui/api/events?token=${token}`)

    eventSource.onopen = () => {
      setConnected(true)
    }

    eventSource.onmessage = (e) => {
      try {
        const event: AuthEvent = JSON.parse(e.data)
        setEvents((prev) => {
          // Add new event at the beginning, keep last 100
          const updated = [event, ...prev]
          return updated.slice(0, 100)
        })
      } catch (err) {
        console.error('Failed to parse event:', err)
      }
    }

    eventSource.onerror = () => {
      setConnected(false)
    }

    return () => {
      eventSource.close()
    }
  }, [token])

  if (!token) {
    return <Unauthorized />
  }

  return (
    <div className="min-h-screen bg-bg-primary flex flex-col">
      {/* Header */}
      <header className="bg-bg-secondary border-b border-bg-card px-4 py-3 flex items-center justify-between">
        <div className="flex items-center gap-4">
          <h1 className="text-lg font-bold text-text-primary">
            Predicate Authority
          </h1>
          <ConnectionStatus connected={connected} />
          <CopyTokenButton token={token} />
        </div>
        <Stats events={events} />
      </header>

      {/* Main content - split pane */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left pane - Policy */}
        <div className="w-1/3 border-r border-bg-card flex flex-col">
          <div className="bg-bg-secondary px-4 py-2 border-b border-bg-card">
            <h2 className="text-sm font-semibold text-text-secondary uppercase tracking-wide">
              Policy
            </h2>
          </div>
          <div className="flex-1 overflow-auto bg-bg-primary">
            <PolicyViewer token={token} />
          </div>
        </div>

        {/* Right pane - Live Feed */}
        <div className="flex-1 flex flex-col">
          <div className="bg-bg-secondary px-4 py-2 border-b border-bg-card flex flex-col gap-2">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-text-secondary uppercase tracking-wide">
                Live Authorization Feed
              </h2>
              <span className="text-xs text-text-secondary">
                {filteredEvents.length}/{events.length} events
              </span>
            </div>
            <FilterControls filters={filters} onChange={setFilters} />
          </div>
          <EventLog events={filteredEvents} />
        </div>
      </div>
    </div>
  )
}
