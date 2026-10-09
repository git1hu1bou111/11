interface RateRow {
  input_tokens: number
  cache_creation_tokens: number
  cache_read_tokens: number
  image_count: number
  image_output_tokens: number
  billing_mode?: string | null
  request_type?: string | null
}

/** 图片/视频计费与压缩类请求没有缓存命中语义，返回空串由调用方决定是否展示。 */
function supportsCacheMetrics(row: RateRow): boolean {
  return row.image_count <= 0
    && row.image_output_tokens <= 0
    && row.billing_mode !== 'image'
    && (!row.request_type || ['sync', 'stream', 'ws_v2', 'cyber'].includes(row.request_type))
}

/** 缓存命中率：缓存读取 ÷（普通输入 + 缓存读取 + 缓存写入）。 */
export function formatCacheHitRate(row: RateRow): string {
  if (!supportsCacheMetrics(row)) return ''
  const read = row.cache_read_tokens || 0
  const write = row.cache_creation_tokens || 0
  const input = row.input_tokens || 0
  const total = read + write + input
  if (!Number.isFinite(total) || total <= 0) return ''
  return `${((read / total) * 100).toFixed(2)}%`
}
