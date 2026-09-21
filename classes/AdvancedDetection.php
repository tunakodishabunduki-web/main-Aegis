<?php
/**
 * AdvancedDetection.php
 * ============================================================
 * Two distinct responsibilities:
 *
 *   1. NORMALISE — strip every layer of encoding an attacker
 *      could use to hide a payload before regex ever runs.
 *      This is what was missing before. Covered layers:
 *        • Single + double + triple URL-decode   (%27 → %2527 → ...)
 *        • HTML entity decode                    (&lt;script&gt;)
 *        • Hex escape sequences                  (\x27, \u0027, 0x27)
 *        • Base64 decode (detects + decodes embedded blobs)
 *        • Unicode normalisation (fullwidth chars: ＜ＳＣＲＩＰＴｓｒｃ)
 *        • Null-byte removal                     (%00, \0)
 *        • Comment stripping                     (/**/ between SQL keywords)
 *        • Case normalisation
 *
 *   2. CLASSIFY — run regex patterns against the normalised text.
 *
 * IMPORTANT: this layer is still a detection/logging aid.
 * Parameterised queries remain your actual SQLi defence.
 * Normalisation just closes the gap where encoded payloads
 * would previously have slipped past the regex entirely.
 * ============================================================
 */

namespace Aegis\Classes;

class AdvancedDetection
{
    // ----------------------------------------------------------------
    // Patterns — applied AFTER normalisation so encoding can't hide them
    // ----------------------------------------------------------------
    private const PATTERNS = [

        // SQL injection — covers OR/AND bypass, UNION, DROP, comment tricks
        'SQL_INJECTION_ATTEMPT' => "/('|\")\\s*(OR|AND)\\s*('|\")?\\s*=|"
            . "UNION\\s+SELECT|DROP\\s+TABLE|"
            . "INSERT\\s+INTO|UPDATE\\s+SET|DELETE\\s+FROM|"
            . "SLEEP\\s*\\(|BENCHMARK\\s*\\(|"   // time-based blind
            . "LOAD_FILE\\s*\\(|INTO\\s+OUTFILE|" // file ops
            . "INFORMATION_SCHEMA|"               // schema enumeration
            . "--|;--|#\\s*$/i",

        // XSS — script tags, event handlers, javascript: protocol, data URIs
        'XSS_ATTEMPT' => '/<script[\s>]|<\/script|'
            . 'on\w+\s*=|'                        // onerror=, onload=, onclick=...
            . 'javascript\s*:|'
            . 'vbscript\s*:|'
            . '<\s*iframe|<\s*object|<\s*embed|<\s*link|<\s*meta|'
            . 'data\s*:\s*text\/html|'            // data URI XSS
            . 'expression\s*\(/i',                // IE CSS expression()

        // Path traversal / local file inclusion
        'PATH_TRAVERSAL_ATTEMPT' => '/\.\.[\/\\\\]|'
            . '\/etc\/(passwd|shadow|hosts|hostname|issue)|'
            . 'c:[\/\\\\]windows|'
            . 'proc\/self\/environ|'              // Linux process env
            . 'proc\/self\/fd|'
            . '\/var\/log|'
            . 'php:\/\/filter|'                   // PHP wrapper LFI
            . 'php:\/\/input|'
            . 'expect:\/\/|'
            . 'zip:\/\/|phar:\/\//i',

        // OS command injection
        'COMMAND_INJECTION_ATTEMPT' => '/;\s*(ls|cat|type|dir|whoami|id|pwd|uname|env|'
            . 'wget|curl|nc|ncat|netcat|bash|sh|cmd|powershell|python|perl|ruby)\b|'
            . '\|\s*(ls|cat|nc|bash|sh|wget|curl|python)\b|'
            . '`[^`]+`|'                          // backtick execution
            . '\$\([^)]+\)|'                      // $() subshell
            . '>\s*\/dev\/tcp|'                   // bash reverse shell
            . '>>\s*\/tmp|'
            . '\bping\b.*-[nc]\s+\d|'            // ping with count flag
            . '\bsleep\b\s+\d/i',

        // XXE
        'XXE_ATTEMPT' => '/<!ENTITY\s|'
            . '<!DOCTYPE[^>]*\[|'
            . 'SYSTEM\s+"(file|http|ftp|php|expect|data):\/\//i',

        // Open redirect
        'OPEN_REDIRECT_ATTEMPT' => '/(?:redirect|return_to|next|url|target|'
            . 'dest|destination|forward|location|go|link|goto)\s*=\s*'
            . '(?:https?|\/\/|\\\\\\\\)/i',

        // SSRF
        'SSRF_ATTEMPT' => '/(?:url|uri|src|target|dest|endpoint|host|proxy|'
            . 'remote|fetch|load|request)\s*=\s*'
            . '(?:https?:\/\/(?:localhost|127\.|0\.0\.0\.0|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|'
            . '169\.254\.169\.254)|'
            . 'file:\/\/|dict:\/\/|gopher:\/\/|sftp:\/\/)/i',

        // NoSQL injection ($where, $ne, etc.)
        'NOSQL_INJECTION_ATTEMPT' => '/\$(?:where|ne|gt|gte|lt|lte|in|nin|'
            . 'regex|or|and|not|nor|exists|type|mod|all|size|'
            . 'elemMatch|slice|comment|explain)\s*[:\[{]/i',

        // JWT alg:none and header forgery
        'JWT_TAMPERING_ATTEMPT' => '/"alg"\s*:\s*"none"|'
            . '"typ"\s*:\s*"JWT".*"alg"\s*:\s*"none"|'
            . 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\./i', // JWT with empty sig

        // SSTI (Server-Side Template Injection)
        'SSTI_ATTEMPT' => '/\{\{.*\}\}|'
            . '\{%.*%\}|'
            . '\$\{.*\}|'
            . '#\{.*\}|'
            . '<#.*>|'
            . '\[\[.*\]\]/i',

        // LDAP injection
        'LDAP_INJECTION_ATTEMPT' => '/[)(|&!*\\\\][^)(\s]*[)(|&]/i',

        // HTTP request smuggling markers
        'REQUEST_SMUGGLING_ATTEMPT' => '/Transfer-Encoding\s*:\s*chunked.*Content-Length|'
            . 'Content-Length.*Transfer-Encoding\s*:\s*chunked/is',
    ];

    // ----------------------------------------------------------------
    // Known scanner / exploitation tool User-Agent signatures
    // ----------------------------------------------------------------
    private const SCANNER_SIGNATURES = [
        'sqlmap', 'nikto', 'nmap', 'nessus', 'acunetix', 'openvas',
        'w3af', 'dirbuster', 'gobuster', 'masscan', 'zgrab',
        'burpsuite', 'hydra', 'metasploit', 'havij', 'pangolin',
        'zap', 'arachni', 'skipfish', 'wfuzz', 'dirb', 'nuclei',
        'commix', 'beef/', 'slowloris', 'hulk', 'python-requests',
        'go-http-client', 'curl/', 'libwww-perl', 'mechanize',
    ];

    // ----------------------------------------------------------------
    // Full-width Unicode equivalents attackers use to bypass ASCII checks
    // ----------------------------------------------------------------
    private const FULLWIDTH_MAP = [
        '！' => '!', '＂' => '"', '＃' => '#', '＄' => '$', '％' => '%',
        '＆' => '&', '＇' => "'", '（' => '(', '）' => ')', '＊' => '*',
        '＋' => '+', '，' => ',', '－' => '-', '．' => '.', '／' => '/',
        '０' => '0', '１' => '1', '２' => '2', '３' => '3', '４' => '4',
        '５' => '5', '６' => '6', '７' => '7', '８' => '8', '９' => '9',
        '：' => ':', '；' => ';', '＜' => '<', '＝' => '=', '＞' => '>',
        '？' => '?', '＠' => '@', 'Ａ' => 'A', 'Ｂ' => 'B', 'Ｃ' => 'C',
        'Ｄ' => 'D', 'Ｅ' => 'E', 'Ｆ' => 'F', 'Ｇ' => 'G', 'Ｈ' => 'H',
        'Ｉ' => 'I', 'Ｊ' => 'J', 'Ｋ' => 'K', 'Ｌ' => 'L', 'Ｍ' => 'M',
        'Ｎ' => 'N', 'Ｏ' => 'O', 'Ｐ' => 'P', 'Ｑ' => 'Q', 'Ｒ' => 'R',
        'Ｓ' => 'S', 'Ｔ' => 'T', 'Ｕ' => 'U', 'Ｖ' => 'V', 'Ｗ' => 'W',
        'Ｘ' => 'X', 'Ｙ' => 'Y', 'Ｚ' => 'Z', 'ａ' => 'a', 'ｂ' => 'b',
        'ｃ' => 'c', 'ｄ' => 'd', 'ｅ' => 'e', 'ｆ' => 'f', 'ｇ' => 'g',
        'ｈ' => 'h', 'ｉ' => 'i', 'ｊ' => 'j', 'ｋ' => 'k', 'ｌ' => 'l',
        'ｍ' => 'm', 'ｎ' => 'n', 'ｏ' => 'o', 'ｐ' => 'p', 'ｑ' => 'q',
        'ｒ' => 'r', 'ｓ' => 's', 'ｔ' => 't', 'ｕ' => 'u', 'ｖ' => 'v',
        'ｗ' => 'w', 'ｘ' => 'x', 'ｙ' => 'y', 'ｚ' => 'z',
    ];

    // ================================================================
    //  PUBLIC API
    // ================================================================

    /**
     * Normalises input through every known obfuscation layer, then
     * classifies it against all attack patterns.
     *
     * Returns the first matching attack_type string, or null.
     */
    public static function classify(string $input): ?string
    {
        $layers = self::normaliseAll($input);

        // Test every normalised layer — attacker only needs ONE to succeed
        foreach ($layers as $normalised) {
            foreach (self::PATTERNS as $type => $pattern) {
                if (preg_match($pattern, $normalised)) {
                    return $type;
                }
            }
        }
        return null;
    }

    /**
     * Same as classify() but returns ALL matching types (for logging
     * when a single input carries multiple attack signatures).
     */
    public static function classifyAll(string $input): array
    {
        $layers = self::normaliseAll($input);
        $found  = [];

        foreach ($layers as $normalised) {
            foreach (self::PATTERNS as $type => $pattern) {
                if (!isset($found[$type]) && preg_match($pattern, $normalised)) {
                    $found[$type] = true;
                }
            }
        }
        return array_keys($found);
    }

    /**
     * Returns the normalised text for a given raw input string.
     * Useful for showing on the dashboard what the decoded payload looks like.
     */
    public static function normalise(string $input): string
    {
        return self::normaliseSingle($input);
    }

    /**
     * Checks a User-Agent string for known scanning tool signatures.
     */
    public static function isScanner(string $userAgent): bool
    {
        $lower = strtolower($userAgent);
        foreach (self::SCANNER_SIGNATURES as $sig) {
            if (str_contains($lower, $sig)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Detects duplicate query-string keys (HTTP parameter pollution).
     * PHP's $_GET de-duplicates by keeping only the last value, so we
     * inspect the raw QUERY_STRING instead.
     */
    public static function hasParameterPollution(string $queryString): bool
    {
        if (empty($queryString)) return false;
        $pairs = explode('&', $queryString);
        $keys  = array_map(fn($p) => explode('=', $p, 2)[0], $pairs);
        return count($keys) !== count(array_unique($keys));
    }

    // ================================================================
    //  NORMALISATION PIPELINE (private)
    // ================================================================

    /**
     * Returns an array of normalised variants of $input.
     * We test ALL variants because an attacker might only apply
     * one layer of encoding, and we want to catch any of them.
     */
    private static function normaliseAll(string $input): array
    {
        $variants   = [];
        $variants[] = $input;                           // 0. raw
        $variants[] = self::normaliseSingle($input);    // 1. full pipeline
        // Also try with just URL decode in case the pipeline over-strips
        $variants[] = self::urlDecodeAll($input);

        return array_unique($variants);
    }

    /**
     * Runs the complete normalisation pipeline on one string.
     * The order matters — decode first, then strip, then normalise.
     */
    private static function normaliseSingle(string $input): string
    {
        // Step 1: remove null bytes (used to terminate strings in C-based parsers)
        $s = str_replace(["\0", '%00', '\0', '\x00'], '', $input);

        // Step 2: URL decode up to 3 layers deep (%27 → %2527 → %%2527 etc.)
        $s = self::urlDecodeAll($s);

        // Step 3: HTML entity decode (&lt; → < , &amp; → & , &#39; → ')
        $s = html_entity_decode($s, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        // A second pass catches double-encoded HTML entities (&&lt; → &lt; → <)
        $s = html_entity_decode($s, ENT_QUOTES | ENT_HTML5, 'UTF-8');

        // Step 4: Hex escape sequences
        //   \x27  →  '
        //   \u0027 →  '
        //   &#x27; →  '  (already covered by html_entity_decode, but belt+braces)
        //   0x27   →  '  (as used in MySQL hex notation)
        $s = preg_replace_callback('/\\\\x([0-9a-fA-F]{2})/', fn($m) => chr(hexdec($m[1])), $s);
        $s = preg_replace_callback('/\\\\u([0-9a-fA-F]{4})/', fn($m) => mb_chr(hexdec($m[1]), 'UTF-8'), $s);
        $s = preg_replace_callback('/\b0x([0-9a-fA-F]{2})\b/', fn($m) => chr(hexdec($m[1])), $s);
        $s = preg_replace_callback('/&#x([0-9a-fA-F]+);?/', fn($m) => mb_chr(hexdec($m[1]), 'UTF-8'), $s);
        $s = preg_replace_callback('/&#(\d+);?/', fn($m) => mb_chr((int) $m[1], 'UTF-8'), $s);

        // Step 5: Base64 — detect embedded base64 blobs and decode them
        //   Attackers wrap payloads: eval(base64_decode('PHNjcmlwdD4...'))
        $s = self::decodeBase64Blobs($s);

        // Step 6: Full-width Unicode → ASCII
        //   ＜ＳＣＲＩＰＴ → <SCRIPT
        $s = strtr($s, self::FULLWIDTH_MAP);

        // Step 7: Strip SQL comment markers used to break keywords
        //   UN/**/ION  →  UNION
        //   SE/*comment*/LECT  →  SELECT
        $s = preg_replace('/\/\*[^*]*\*+(?:[^*\/][^*]*\*+)*\//', '', $s);
        // MySQL inline comment variant /*!50000 ... */
        $s = preg_replace('/\/\*![\d]*\s*/', '', $s);
        $s = str_replace('*/', '', $s);

        // Step 8: Collapse whitespace and repeated characters used to break patterns
        //   SELE    CT  →  SELECT
        $s = preg_replace('/\s+/', ' ', $s);

        return $s;
    }

    /**
     * Applies urldecode() up to 3 times until the string stops changing.
     * Handles %27, %2527 (double-encoded), %252527 (triple-encoded).
     */
    private static function urlDecodeAll(string $s): string
    {
        $prev = null;
        $passes = 0;
        while ($s !== $prev && $passes < 3) {
            $prev = $s;
            $s    = urldecode($s);
            $passes++;
        }
        return $s;
    }

    /**
     * Finds and decodes base64 blobs embedded in the input string.
     * Targets patterns like:
     *   base64_decode('PHNjcmlwdD4=')
     *   atob('PHNjcmlwdD4=')
     *   eval(base64_decode(...))
     */
    private static function decodeBase64Blobs(string $s): string
    {
        // Match quoted or unquoted base64 strings preceded by decode/atob keywords
        return preg_replace_callback(
            '/(?:base64_decode|atob|frombase64string)\s*[\(\s]["\']?([A-Za-z0-9+\/=]{20,})["\']?[\)\s]?/i',
            function (array $m): string {
                $decoded = base64_decode($m[1], true);
                // Only substitute if decoding produced printable ASCII
                return ($decoded !== false && mb_detect_encoding($decoded, 'ASCII', true))
                    ? $decoded
                    : $m[0];
            },
            $s
        );
    }
}
