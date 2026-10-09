import { describe, expect, it } from 'vitest'
import { formatCacheHitRate, formatEffectiveOutputRate } from '../usageRateMetrics'

const baseRow = {
  input_tokens: 0,
  output_tokens: 0,
  cache_creation_tokens: 0,
  cache_read_tokens: 0,
  duration_ms: null as number | null,
  first_token_ms: null as number | null,
  image_count: 0,
  image_output_tokens: 0,
  billing_mode: 'token' as string | null,
  request_type: 'stream',
}

describe('formatCacheHitRate', () => {
  it('computes reads divided by plain input plus cache reads and writes', () => {
    // 参考面板口径：~170.8K 读取 /（读取 + 写入 + 普通输入）显示为 98.5%
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

describe('formatEffectiveOutputRate', () => {
  it('excludes first-token latency from the denominator', () => {
    // 参考面板口径：1,175 输出 / (42.16s − 11.99s) ≈ 38.9 t/s
    expect(formatEffectiveOutputRate({
      ...baseRow,
      output_tokens: 1_175,
      duration_ms: 42_160,
      first_token_ms: 11_990,
    })).toBe('38.9 t/s')
  })

  it('falls back to total duration without first-token timing', () => {
    expect(formatEffectiveOutputRate({
      ...baseRow,
      output_tokens: 298,
      duration_ms: 4_670,
    })).toBe('63.8 t/s')
  })

  it('returns empty when output tokens are missing', () => {
    expect(formatEffectiveOutputRate({ ...baseRow, duration_ms: 1_000 })).toBe('')
  })
})
