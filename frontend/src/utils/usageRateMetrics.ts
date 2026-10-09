interface RateRow {
  input_tokens: number
  output_tokens: number
  cache_creation_tokens: number
  cache_read_tokens: number
  duration_ms: number | null
  first_token_ms: number | null
  image_count: number
  image_output_tokens: number
  billing_mode?: string | null
  request_type?: string | null
}

/** 图片/视频计费与压缩类请求没有缓存命中和输出速率语义，返回空串由调用方决定占位。 */
function supportsRateMetrics(row: RateRow): boolean {
  return row.image_count <= 0
    && row.image_output_tokens <= 0
    && row.billing_mode !== 'image'
    && (!row.request_type || ['sync', 'stream', 'ws_v2', 'cyber'].includes(row.request_type))
}

/** 缓存命中率：缓存读取 ÷（普通输入 + 缓存读取 + 缓存写入）。 */
export function formatCacheHitRate(row: RateRow): string {
  if (!supportsRateMetrics(row)) return ''
  const read = row.cache_read_tokens || 0
  const write = row.cache_creation_tokens || 0
  const input = row.input_tokens || 0
  const total = read + write + input
  if (!Number.isFinite(total) || total <= 0) return ''
  return `${((read / total) * 100).toFixed(2)}%`
}

/** 单次输出 TPS（剔除首字延迟口径）：输出 Token ÷（总耗时 − 首字延迟）。 */
export function formatEffectiveOutputRate(row: RateRow): string {
  if (!supportsRateMetrics(row)) return ''
  const outputTokens = row.output_tokens
  const durationMs = row.duration_ms
  if (!Number.isFinite(outputTokens) || outputTokens <= 0
    || durationMs == null || !Number.isFinite(durationMs) || durationMs <= 0) {
    return ''
  }
  const firstTokenMs = row.first_token_ms != null && row.first_token_ms > 0 && row.first_token_ms < durationMs
    ? row.first_token_ms
    : 0
  return `${((outputTokens * 1000) / (durationMs - firstTokenMs)).toFixed(1)} t/s`
}
