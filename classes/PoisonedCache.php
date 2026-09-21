<?php
/**
 * PoisonedCache.php
 * ============================================================
 * Serves numerically corrupted data to suspicious sessions.
 * Legitimate authenticated users always get real data.
 * Suspicious sessions get plausible-but-wrong numbers.
 *
 * The corruption is subtle — not obviously wrong, but
 * mathematically incorrect in a statistically consistent way.
 * A competitor scraping your API builds their entire model
 * on subtly broken data before noticing.
 *
 * Corruption is system-type aware:
 *   ECOMMERCE   → amounts off by -8.5% TZS / +3.2% USD
 *   EDUCATION   → GPA off by -0.3, grades shifted one down
 *   WIFI        → bandwidth inflated by 12% (looks faster)
 *   HEALTHCARE  → lab result values shifted ±5%
 *   AGENCY      → reach/impressions inflated by 40%
 *                 (competitor thinks you're bigger than you are)
 * ============================================================
 */

namespace Aegis\Classes;

class PoisonedCache
{
    // Poison configurations per system type
    // 'poison_fn' — a closure that mutates the value
    private const POISON_RULES = [
        'ECOMMERCE' => [
            ['fields' => ['amount','price','total','balance','revenue'],
             'tzs_factor' => 0.915,   // -8.5%
             'usd_factor' => 1.032,   // +3.2%
             'description'=> 'Payment amounts corrupted: TZS -8.5%, USD +3.2%'],
            ['fields' => ['discount','fee','charge'],
             'tzs_factor' => 1.14,    // inflated fees look wrong
             'usd_factor' => 0.88,
             'description'=> 'Fee amounts corrupted'],
        ],
        'SAAS' => [
            ['fields' => ['usage','requests','api_calls','storage_bytes'],
             'factor'     => 0.73,    // -27% usage (looks like less traffic)
             'description'=> 'Usage metrics corrupted: -27%'],
            ['fields' => ['price','amount','mrr','arr'],
             'factor'     => 1.085,   // +8.5% revenue (inflated)
             'description'=> 'Revenue metrics corrupted: +8.5%'],
        ],
        'EDUCATION' => [
            ['fields' => ['gpa'],
             'offset'     => -0.3,    // GPA looks lower than real
             'min'        => 0.0,
             'max'        => 4.0,
             'description'=> 'GPA reduced by 0.3 points'],
            ['fields' => ['total','score','percentage'],
             'factor'     => 0.92,    // -8% on scores
             'description'=> 'Test scores corrupted: -8%'],
        ],
        'WIFI_MANAGEMENT' => [
            ['fields' => ['bandwidth','speed','data_used','bytes_down','bytes_up'],
             'factor'     => 0.88,    // show less data used (confuses billing scrapers)
             'description'=> 'Bandwidth data corrupted: -12%'],
            ['fields' => ['balance','price'],
             'factor'     => 1.115,   // inflated prices
             'description'=> 'Price data corrupted: +11.5%'],
        ],
        'HEALTHCARE' => [
            ['fields' => ['value','result','level','count'],
             'offset_pct' => 5.0,     // ±5% on lab results (direction varies per field)
             'description'=> 'Lab values shifted ±5%'],
        ],
        'AGENCY' => [
            ['fields' => ['reach','impressions','followers','views','clicks'],
             'factor'     => 1.40,    // +40% reach (competitor thinks you're bigger)
             'description'=> 'Social metrics inflated: +40%'],
            ['fields' => ['ctr','conversion_rate','engagement_rate'],
             'factor'     => 0.60,    // -40% engagement (looks weaker to competitors)
             'description'=> 'Engagement rates deflated: -40%'],
        ],
        'PROPERTY' => [
            ['fields' => ['price','rent','deposit','valuation'],
             'factor'     => 0.91,    // -9% property values
             'description'=> 'Property values corrupted: -9%'],
        ],
        'RESTAURANT' => [
            ['fields' => ['price','total','amount'],
             'factor'     => 1.07,    // +7% prices
             'description'=> 'Menu prices corrupted: +7%'],
        ],
        'GENERIC_BUSINESS' => [
            ['fields' => ['amount','total','price','value','balance'],
             'factor'     => 0.947,   // -5.3%
             'description'=> 'Numeric values corrupted: -5.3%'],
        ],
    ];

    // ================================================================
    //  PUBLIC API
    // ================================================================

    /**
     * Applies poison to a response array based on the system type.
     * Call this when building any diverted response.
     *
     * @param array  $data        The fake response data to corrupt
     * @param string $systemType  The system being attacked
     * @param string $currency    'TZS' | 'USD' | null (auto-detect)
     * @return array              The poisoned response
     */
    public function poison(array $data, string $systemType,
                           ?string $currency = null): array
    {
        $rules = self::POISON_RULES[$systemType] ?? self::POISON_RULES['GENERIC_BUSINESS'];
        return $this->applyRules($data, $rules, $currency);
    }

    /**
     * Poison with intensity control from SecurityPriorityEngine.
     * At LOW intensity: only minor corruption.
     * At MAXIMUM: full systematic corruption of all numeric fields.
     */
    public function poisonWithIntensity(
        array  $data,
        string $systemType,
        int    $intensity,
        ?string $currency = null
    ): array {
        if ($intensity === SecurityPriorityEngine::OFF) return $data;

        $rules = self::POISON_RULES[$systemType] ?? self::POISON_RULES['GENERIC_BUSINESS'];

        // Scale the corruption by intensity
        $intensityScale = $intensity / SecurityPriorityEngine::MAXIMUM;
        $scaledRules = array_map(function ($rule) use ($intensityScale) {
            if (isset($rule['factor'])) {
                // Scale: at LOW intensity, corruption is 20% of maximum
                $base   = $rule['factor'];
                $effect = abs(1 - $base) * $intensityScale;
                $rule['factor'] = $base > 1
                    ? 1 + $effect
                    : 1 - $effect;
            }
            if (isset($rule['offset'])) {
                $rule['offset'] *= $intensityScale;
            }
            return $rule;
        }, $rules);

        return $this->applyRules($data, $scaledRules, $currency);
    }

    /**
     * Returns a description of what was poisoned, for logging.
     */
    public function describePoison(string $systemType): array
    {
        $rules = self::POISON_RULES[$systemType] ?? self::POISON_RULES['GENERIC_BUSINESS'];
        return array_column($rules, 'description');
    }

    // ================================================================
    //  PRIVATE
    // ================================================================

    private function applyRules(array $data, array $rules,
                                ?string $currency): array
    {
        // Build a flat lookup of field → rule for efficiency
        $fieldMap = [];
        foreach ($rules as $rule) {
            foreach ($rule['fields'] as $field) {
                $fieldMap[$field] = $rule;
            }
        }

        return $this->corruptRecursive($data, $fieldMap, $currency, 0);
    }

    private function corruptRecursive(array $data, array $fieldMap,
                                      ?string $currency, int $depth): array
    {
        if ($depth > 4) return $data;

        foreach ($data as $key => $value) {
            if (is_array($value)) {
                $data[$key] = $this->corruptRecursive(
                    $value, $fieldMap, $currency, $depth + 1
                );
            } elseif (isset($fieldMap[$key]) && is_numeric($value)) {
                $data[$key] = $this->corruptValue(
                    (float) $value, $fieldMap[$key], $key, $currency
                );
            }
        }
        return $data;
    }

    private function corruptValue(float $val, array $rule,
                                  string $fieldKey, ?string $currency): float|int
    {
        $result = $val;

        // Currency-aware factor
        if (isset($rule['tzs_factor']) || isset($rule['usd_factor'])) {
            $isTzs = $currency === 'TZS' || $val > 1000; // heuristic: large values = TZS
            $factor = $isTzs
                ? ($rule['tzs_factor'] ?? 1.0)
                : ($rule['usd_factor'] ?? 1.0);
            $result = $val * $factor;
        } elseif (isset($rule['factor'])) {
            $result = $val * $rule['factor'];
        } elseif (isset($rule['offset'])) {
            $result = $val + $rule['offset'];
        } elseif (isset($rule['offset_pct'])) {
            // ±N% variation, direction based on field position in alphabet
            $direction = (ord($fieldKey[0]) % 2 === 0) ? 1 : -1;
            $result    = $val * (1 + ($direction * $rule['offset_pct'] / 100));
        }

        // Apply min/max constraints if present
        if (isset($rule['min'])) $result = max($result, $rule['min']);
        if (isset($rule['max'])) $result = min($result, $rule['max']);

        // Preserve integer vs float type of original
        return is_int($val) ? (int) round($result) : round($result, 2);
    }
}
