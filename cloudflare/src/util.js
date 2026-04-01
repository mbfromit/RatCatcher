export function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' }
  })
}

export function checkAdminPassword(request, env) {
  return request.headers.get('X-Admin-Password') === env.ADMIN_PASSWORD
}
