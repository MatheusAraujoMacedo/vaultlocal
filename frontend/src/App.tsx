import { Routes, Route, Navigate } from 'react-router-dom'
import Login from './pages/Login'
import Register from './pages/Register'
import Vault from './pages/Vault'
import EntryDetail from './pages/EntryDetail'
import EntryForm from './pages/EntryForm'
import Health from './pages/Health'
import { useEffect, useState } from 'react'

export default function App() {
  const [authed, setAuthed] = useState<boolean | null>(null)

  useEffect(() => {
    try {
      const raw = sessionStorage.getItem('vaultlocal_tokens')
      if (!raw) {
        setAuthed(false)
        return
      }
      const parsed = JSON.parse(raw) as { access?: string }
      setAuthed(!!parsed.access)
    } catch {
      setAuthed(false)
    }
  }, [])

  if (authed === null) return null

  return (
    <Routes>
      <Route path="/login" element={<Login onLogin={() => setAuthed(true)} />} />
      <Route path="/register" element={<Register />} />
      <Route
        path="/"
        element={authed ? <Vault /> : <Navigate to="/login" replace />}
      />
      <Route
        path="/entry/new"
        element={authed ? <EntryForm /> : <Navigate to="/login" replace />}
      />
      <Route
        path="/entry/:id"
        element={authed ? <EntryDetail /> : <Navigate to="/login" replace />}
      />
      <Route
        path="/entry/:id/edit"
        element={authed ? <EntryForm /> : <Navigate to="/login" replace />}
      />
      <Route
        path="/health"
        element={authed ? <Health /> : <Navigate to="/login" replace />}
      />
    </Routes>
  )
}
