import { describe, expect, it } from 'vitest'
import { formatCacheHitRate } from '../usageRateMetrics'

const baseRow = {
  input_tokens: 0,
  cache_creation_tokens: 0,
  cache_read_tokens: 0,
  image_count: 0,
  image_output_tokens: 0,
  billing_mode: 'token' as string | null,
  request_type: 'stream' as string | null,
}

describe('formatCacheHitRate', () => {
  it('computes reads divided by plain input plus cache reads and writes', () => {
    // 参考面板口径：~170.8K 读取 /（读取 + 写入 + 普通输入）≈ 98.5%
    expect(formatCacheHitRate({
      ...baseRow,
      input_tokens: 3,
      cache_read_tokens: 170_800,
      cache_creation_tokens: 2_600,
    })).toBe('98.50%')
  })

  it('returns empty without any token volume', () => {
    expect(formatCacheHitRate(baseRow)).toBe('')
  })

  it('returns empty for image billing requests', () => {
    expect(formatCacheHitRate({
      ...baseRow,
      input_tokens: 100,
      cache_read_tokens: 900,
      image_count: 1,
      billing_mode: 'image',
    })).toBe('')
  })
})
