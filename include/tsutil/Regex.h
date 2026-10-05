/** @file

  A brief file description

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 */

#pragma once

#include <cstdint>
#include <memory>
#include <string_view>
#include <string>
#include <vector>

/// @brief Match flags for regular expression evaluation.
///
/// @internal These values are copied from pcre2.h, to avoid having to include it.  The values are checked (with
/// static_assert) in Regex.cc against PCRE2 named constants, in case they change in future PCRE2 releases.
enum REFlags {
  RE_CASE_INSENSITIVE = 0x00000008u, ///< Ignore case (by default, matches are case sensitive).
  RE_UNANCHORED       = 0x00000400u, ///< Unanchored (@a DFA defaults to anchored).
  RE_ANCHORED         = 0x80000000u, ///< Anchored (@a Regex defaults to unanchored).
  RE_ENDANCHORED      = 0x20000000u, ///< Anchored at the subject end; with RE_ANCHORED, requires a whole-subject match.
  RE_NOTEMPTY         = 0x00000004u, ///< Not empty (by default, matches may match empty string).
  /// Require the match to consume the entire subject. When set, a successful pcre2 match
  /// that does not span [0, subject.size()) is reported as @c RE_ERROR_NOMATCH. Implemented
  /// as a post-match length check so JIT remains eligible on all supported PCRE2 versions.
  RE_FULL_MATCH = 0x10000000u,
  /// Refuse a pattern that turns on UTF mode with a leading @c (*UTF) verb.
  ///
  /// In UTF mode pcre2 validates each subject as UTF-8 before matching it, so a subject holding a
  /// byte that is not valid UTF-8 returns @c PCRE2_ERROR_UTF8_ERR* rather than a match verdict.
  /// A caller that supplies only the pattern can therefore change the outcome for subjects it does
  /// not match, which is worth refusing where the pattern is untrusted and the subjects are known
  /// to be plain bytes. It is not worth refusing for a pattern an operator wrote in a configuration
  /// file: @c (*UTF) is documented for those (admin-guide/configuration/regex-best-practices), so
  /// this is opt-in rather than applied to every compile.
  ///
  /// @note This does not keep matching on the JIT. Measured against PCRE2 10.47, a @c (*UTF)
  /// pattern JIT-compiles and runs there like any other; the verb that does force the interpreter
  /// is @c (*NO_JIT), which pcre2 offers no way to refuse.
  RE_NEVER_UTF = 0x00001000u,
};

/// @brief Error codes returned by regular expression operations.
///
/// @internal As with REFlags, these values are copied from pcre2.h, to avoid having to include it.
enum REErrors {
  RE_ERROR_NOMATCH    = -1,  ///< No match found.
  RE_ERROR_MATCHLIMIT = -47, ///< Match limit exhausted; the match has no verdict.
  /// Nothing was matched, because something the match needs was missing -- for example no
  /// compiled pattern, no match data, or a caller-supplied RegexMatchContext that holds nothing
  /// because its allocation failed. Checking compile() does not rule this code out.
  /// RecLookupMatchingRecords folds it into its undecided count rather than special-casing it,
  /// because the record was not evaluated and so must be reported, not dropped silently.
  RE_ERROR_NULL = -51
};

/// @brief Wrapper for PCRE2 match data.
class RegexMatches
{
  friend class Regex;

public:
  /** Construct a new RegexMatches object.
   *
   * @param size The number of matches to allocate space for.
   */
  RegexMatches(uint32_t size = DEFAULT_MATCHES);
  ~RegexMatches();

  /** Get the match at the given index.
   *
   * @return The match at the given index, or an empty view.
   */
  std::string_view operator[](size_t index) const;
  /** Get the ovector pointer for the capture groups.  Don't use this unless you know what you are doing.
   *
   * @return ovector pointer.
   */
  size_t *get_ovector_pointer();
  int32_t size() const;

private:
  constexpr static uint32_t DEFAULT_MATCHES = 10;
  static void              *malloc(size_t size, void *caller);
  static void               free(void *p, void *caller);
  std::string_view          _subject;
  char    _buffer[24 + 96 + 28 * DEFAULT_MATCHES]; // 24 bytes for the general context, 96 bytes overhead, 28 bytes per match.
  size_t  _buffer_bytes_used = 0;
  int32_t _size              = 0;

  /// @internal This effectively wraps a void* so that we can avoid requiring the pcre2.h include for the user of the Regex
  /// API (see Regex.cc).
  struct _MatchData;
  class _MatchDataPtr
  {
    friend struct _MatchData;

  private:
    void *_ptr = nullptr;
  };
  _MatchDataPtr _match_data;
};

/// @brief Wrapper for PCRE2 match context
///
/// @internal This instance is not tied to any Regex and can be used with one of the Regex::exec overloads.
class RegexMatchContext
{
  friend class Regex;

public:
  /** Construct a new RegexMatchContext object.
   */
  RegexMatchContext();
  ~RegexMatchContext();

  /// uses pcre2_match_context_copy for a deep copy.
  RegexMatchContext(RegexMatchContext const &orig);
  RegexMatchContext &operator=(RegexMatchContext const &orig);

  /// @internal These are defaulted and therefore wrong: the member is a raw pointer to an owning
  /// allocation, so both objects are left pointing at it and the second destructor frees it again.
  /// That is pre-existing -- it was equally true when the pointer owned the pcre2 context directly
  /// -- and nothing in the tree moves one of these, so it is latent. Not fixed here on purpose:
  /// defining them emits move symbols that a traffic_server built before this change does not
  /// export, so a plugin built against this header would fail to load into one. The fix belongs
  /// with apache/trafficserver#13663, which replaces this class with a value type.
  RegexMatchContext(RegexMatchContext &&)            = default;
  RegexMatchContext &operator=(RegexMatchContext &&) = default;

  /** Caps the number of backtracking steps one match may take.
   *
   * This bounds the step @b count only. It does not bound the cost of a step, which is a property
   * of the pattern, so it is not a bound on the work a match can do. A pattern can stay inside this
   * limit and still be expensive, and it can be expensive while returning an ordinary verdict.
   *
   * Nor does exceeding it reliably report @c RE_ERROR_MATCHLIMIT. PCRE2 returns whichever resource
   * it exhausted first, and which one that is depends on the pattern: a recursive pattern exhausts
   * the JIT stack instead, and because this context assigns none it reports
   * @c PCRE2_ERROR_JIT_STACKLIMIT (-46) from PCRE2's default 32KB block, or
   * @c PCRE2_ERROR_RECURSELOOP (-52) where JIT is unavailable. Depth and heap limits have their own
   * codes again.
   *
   * So a caller that wants to know whether a match reached a verdict must treat every negative code
   * other than @c RE_ERROR_NOMATCH as "no verdict", rather than testing for any particular one. A
   * caller that wants to bound work needs something other than this limit.
   */
  void set_match_limit(uint32_t limit);

  /** The step cap installed by @c set_match_limit, or zero if none was installed.
   *
   * Report this rather than the value a caller intended to install, so that a diagnostic names the
   * cap actually installed on the context. A pattern can lower the limit applied with an inline
   * (*LIMIT_MATCH=n), which this does not see, but cannot raise it, so the value is an upper bound
   * on the limit a match runs under.
   *
   * @note Zero has three meanings. The context may hold a pcre2 context with no cap installed, in
   * which case matching runs under PCRE2's own compiled-in default unless the pattern lowers it,
   * and that default is not unbounded. @c set_match_limit(0) may have installed a cap of zero. Or
   * the context may hold nothing, because its allocation failed or because it was copied from one
   * that did, in which case Regex::exec refuses to match and returns RE_ERROR_NULL. No caller in
   * the tree installs zero. A diagnostic should say which case applies rather than print the number.
   */
  uint32_t match_limit() const;

private:
  /// @internal This wraps a void* so to avoid requiring a pcre2 include.
  ///
  /// @internal The pointer addresses a holder that carries the pcre2 match context @b and the step
  /// cap installed on it, because pcre2 offers no getter for a limit once set. Keeping that value
  /// behind this pointer rather than as a member here is deliberate: this class is in an installed
  /// header and is embedded by value in already-built plugins (regex_remap and esi both hold one),
  /// so widening it would move the layout they allocate. See src/tsutil/Regex.cc.
  struct _MatchContext;
  struct _MatchContextPtr {
    void *_ptr = nullptr;
  };

  _MatchContextPtr _match_context;
};

/// @brief Wrapper for PCRE2 regular expression.
class Regex
{
public:
  Regex() = default;
  /** Deep copy constructor.
   *
   * Creates a new Regex object with a deep copy of the compiled pattern.
   * Uses pcre2_code_copy() to duplicate the compiled pattern without
   * requiring the original pattern string, then compiles the copy for the
   * just-in-time engine, which pcre2_code_copy() cannot carry over.
   *
   * @param other The Regex object to copy from.
   */
  Regex(Regex const &other);
  /** Deep copy assignment operator.
   *
   * Replaces the current compiled pattern with a deep copy of the other's pattern.
   *
   * @param other The Regex object to copy from.
   * @return Reference to this object.
   */
  Regex &operator=(Regex const &other);
  Regex(Regex &&that) noexcept;
  Regex &operator=(Regex &&other);
  ~Regex();

  /** Compile the @a pattern into a regular expression.
   *
   * @param pattern Source pattern for regular expression.
   * @param flags Compilation flags.
   * @return @a true if compiled successfully, @a false otherwise.
   *
   * @a flags should be the bitwise @c or of @c REFlags values.
   *
   * On failure any previously compiled pattern is left in place and remains usable.
   */
  bool compile(std::string_view pattern, uint32_t flags = 0);

  /** Compile the @a pattern into a regular expression that drives a policy decision.
   *
   * @param pattern Source pattern for regular expression.
   * @param flags Compilation flags.
   * @param policy_gate Operator-facing label identifying this pattern as a policy gate.
   * @return @a true if compiled successfully, @a false otherwise.
   *
   * @a flags should be the bitwise @c or of @c REFlags values.
   *
   * A non-empty @a policy_gate marks @a pattern as operator-authored input that
   * drives a policy decision, subjecting it to @c policy_gate_anchoring. The label
   * names the site in diagnostics, e.g. @c "url_sig excl_regex".
   *
   * @internal This is a distinct overload rather than a defaulted third parameter
   * on the two-argument form. A default argument is supplied at the call site, so
   * appending one changes the mangled name and every plugin already built against
   * the old header fails to load with an undefined symbol for @c Regex::compile.
   *
   * @internal Dropping @a policy_gate at a call site selects the two-argument
   * overload and compiles clean, leaving that site neither anchored nor reported.
   * The two-argument form has to stay reachable for the plugins above, so this is
   * covered by tests at the gate sites rather than by the signature.
   */
  bool compile(std::string_view pattern, uint32_t flags, std::string_view policy_gate);

  /** Compile the @a pattern into a regular expression.
   *
   * @param pattern Source pattern for regular expression.
   * @param error String to receive error message.
   * @param erroffset Pointer to integer to receive error offset.
   * @param flags Compilation flags.
   * @return @a true if compiled successfully, @a false otherwise.
   *
   * @a flags should be the bitwise @c or of @c REFlags values.
   *
   * On failure any previously compiled pattern is left in place and remains usable.
   */
  bool compile(std::string_view pattern, std::string &error, int &erroffset, unsigned flags = 0);

  /** Compile the @a pattern into a regular expression that drives a policy decision.
   *
   * @param pattern Source pattern for regular expression.
   * @param error String to receive error message.
   * @param erroffset Pointer to integer to receive error offset.
   * @param flags Compilation flags.
   * @param policy_gate Operator-facing label identifying this pattern as a policy gate.
   * @return @a true if compiled successfully, @a false otherwise.
   *
   * @a flags should be the bitwise @c or of @c REFlags values.
   *
   * @internal A distinct overload for the same ABI reason as the two-argument form.
   */
  bool compile(std::string_view pattern, std::string &error, int &erroffset, unsigned flags, std::string_view policy_gate);

  /** Process-wide anchoring policy for policy-gate patterns.
   *
   * Non-zero anchors gate patterns to the whole subject. Zero (the default) leaves
   * matching unchanged and warns instead. Read at compile time, so a change takes
   * effect as configurations are reloaded.
   *
   * @internal tsutil cannot depend on librecords, so the owning process links this
   * with @c RecEstablishStaticConfigInt32. Plugins share the variable, so they need
   * no plumbing of their own.
   */
  static int32_t policy_gate_anchoring;

  /** What a policy-gate report is telling the operator. */
  enum class PolicyGateReport {
    UNENFORCED, ///< The policy is off and this pattern is not required to match the whole subject.
    ENFORCED,   ///< The policy anchored this pattern to the whole subject.
  };

  /** Handler invoked when a policy-gate pattern is compiled.
   *
   * @a message is a complete sentence. @a kind selects the severity: @c UNENFORCED is
   * a warning, @c ENFORCED is informational, since under enforcement the pattern is
   * safe and the operator only needs a record that the policy touched it. Null (the
   * default) stays silent.
   *
   * @internal A function pointer because tsutil must not reference the diagnostics
   * implementation: a @c Regex.cc to @c DbgCtl.cc edge pulls that object into every
   * target linking @c libtsutil.a, colliding with the stubs some plugin tests
   * provide and with the ODR constraint in @c plugins/esi/lib/CMakeLists.txt.
   */
  using PolicyGateReportHandler = void (*)(PolicyGateReport kind, std::string_view message);

  static PolicyGateReportHandler policy_gate_report_handler;

  /** Execute the regular expression.
   *
   * @param subject String to match against.
   * @return @c true if the pattern matched, @a false if not.
   *
   * It is safe to call this method concurrently on the same instance of @a this.
   */
  bool exec(std::string_view subject) const;

  /** Execute the regular expression.
   *
   * @param subject String to match against.
   * @param flags Match flags (e.g., RE_NOTEMPTY).
   * @return @c true if the pattern matched, @a false if not.
   *
   * It is safe to call this method concurrently on the same instance of @a this.
   */
  bool exec(std::string_view subject, uint32_t flags) const;

  /** Execute the regular expression.
   *
   * @param subject String to match against.
   * @param matches Place to store the capture groups.
   * @return @c The number of capture groups. < 0 if an error occurred. 0 if the number of Matches is too small.
   *
   * It is safe to call this method concurrently on the same instance of @a this.
   *
   * Each capture group takes 3 elements of @a ovector, therefore @a ovecsize must
   * be a multiple of 3 and at least three times the number of desired capture groups.
   */
  int exec(std::string_view subject, RegexMatches &matches) const;

  /** Execute the regular expression.
   *
   * @param subject String to match against.
   * @param matches Place to store the capture groups.
   * @param flags Match flags (e.g., RE_NOTEMPTY).
   * @param optional context Match context (set matching limits).
   * @return @c The number of capture groups. < 0 if an error occurred. 0 if the number of Matches is too small.
   *
   * It is safe to call this method concurrently on the same instance of @a this.
   *
   * Each capture group takes 3 elements of @a ovector, therefore @a ovecsize must
   * be a multiple of 3 and at least three times the number of desired capture groups.
   */
  int exec(std::string_view subject, RegexMatches &matches, uint32_t flags,
           RegexMatchContext const *const matchContext = nullptr) const;

  /** Error string for exec failure.
   *
   * @param int return code from exec call.
   */
  static std::string get_error_string(int rc);

  /// @return The number of capture groups in the compiled pattern, -1 for fail.
  int32_t get_capture_count() const;

  /// @return number of highest back references, -1 for fail.
  int32_t get_backref_max() const;

  /// @return Is the compiled pattern empty?
  bool empty() const;

private:
  /// @internal This effectively wraps a void* so that we can avoid requiring the pcre2.h include for the user of the Regex
  /// API (see Regex.cc).
  struct _Code;
  class _CodePtr
  {
    friend struct _Code;

  private:
    void *_ptr = nullptr;
  };
  _CodePtr _code;
};

/** Deterministic Finite state Automata container.
 *
 * This contains a set of patterns (which may be of size 1) and matches if any of the patterns
 * match.
 */
class DFA
{
public:
  DFA() = default;
  ~DFA();

  /// @return The number of patterns successfully compiled.
  int32_t compile(const std::string_view pattern, unsigned flags = 0);
  /// @return The number of patterns successfully compiled.
  int32_t compile(const std::string_view *const patterns, int npatterns, unsigned flags = 0);
  /// @return The number of patterns successfully compiled.
  int32_t compile(const char *const *patterns, int npatterns, unsigned flags = 0);

  /** Match @a str against the internal patterns.
   *
   * @param str String to match.
   * @return Index of the matched pattern, -1 if no match.
   */
  int32_t match(std::string_view str) const;

private:
  struct Pattern {
    Pattern(Regex &&rxp, std::string &&s) : _re(std::move(rxp)), _p(std::move(s)) {}
    Regex       _re; ///< The compile pattern.
    std::string _p;  ///< The original pattern.
  };

  /** Compile @a pattern and add it to the pattern set.
   *
   * @param pattern Regular expression to compile.
   * @param flags Regular expression compilation flags.
   * @return @c true if @a pattern was successfully compiled, @c false if not.
   */
  bool build(std::string_view pattern, unsigned flags = 0);

  std::vector<Pattern> _patterns;
  bool                 _full_match = false; ///< Apply RE_FULL_MATCH on every match() call.
};
