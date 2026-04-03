import { handleSubmit }                                    from './handlers/submit.js'
import { handleSubmissions, handleStats, handleReport, handleDeleteSubmission, handleExport, handleUserSubmissions } from './handlers/api.js'
import { handleDashboard }                                 from './handlers/dashboard.js'
import { handleGetAcks, handlePostAck, handleDeleteAck, handleUpdateFindingsCount } from './handlers/ack.js'
import { handleUserReport }                                from './handlers/userReport.js'

export default {
  async fetch(request, env, ctx) {
    const url  = new URL(request.url)
    const path = url.pathname
    const method = request.method

    if (path === '/ratcatcher/submit') {
      if (method !== 'POST') return new Response('Method Not Allowed', { status: 405 })
      return handleSubmit(request, env)
    }

    const deleteMatch = path.match(/^\/ratcatcher\/api\/submissions\/([^/]+)$/)
    if (deleteMatch && method === 'DELETE') {
      return handleDeleteSubmission(request, env, deleteMatch[1])
    }

    const fcMatch = path.match(/^\/ratcatcher\/api\/submissions\/([^/]+)\/findings-count$/)
    if (fcMatch && method === 'PUT') {
      return handleUpdateFindingsCount(request, env, fcMatch[1])
    }

    const ackHashMatch = path.match(/^\/ratcatcher\/api\/submissions\/([^/]+)\/acks\/([a-f0-9]+)$/)
    if (ackHashMatch) {
      if (method === 'DELETE') return handleDeleteAck(request, env, ackHashMatch[1], ackHashMatch[2])
      return new Response('Method Not Allowed', { status: 405 })
    }

    const ackMatch = path.match(/^\/ratcatcher\/api\/submissions\/([^/]+)\/acks$/)
    if (ackMatch) {
      if (method === 'GET')  return handleGetAcks(request, env, ackMatch[1])
      if (method === 'POST') return handlePostAck(request, env, ackMatch[1])
      return new Response('Method Not Allowed', { status: 405 })
    }

    if (method !== 'GET') return new Response('Method Not Allowed', { status: 405 })

    if (path === '/ratcatcher/dashboard')             return handleDashboard(request, env)
    if (path === '/ratcatcher/api/submissions')       return handleSubmissions(request, env)
    if (path === '/ratcatcher/api/stats')             return handleStats(request, env)
    if (path === '/ratcatcher/api/export')            return handleExport(request, env)
    if (path === '/ratcatcher/api/user-submissions')  return handleUserSubmissions(request, env)

    const reportMatch = path.match(/^\/ratcatcher\/api\/report\/([^/]+)\/(brief|full)$/)
    if (reportMatch) return handleReport(request, env, reportMatch[1], reportMatch[2])

    const userReportMatch = path.match(/^\/ratcatcher\/api\/user-report\/([^/]+)\/(brief|full)$/)
    if (userReportMatch) return handleUserReport(request, env, userReportMatch[1], userReportMatch[2])

    return new Response('Not Found', { status: 404 })
  }
}
