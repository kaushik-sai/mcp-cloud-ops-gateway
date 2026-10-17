// Package policy decides whether a principal may call a tool with given arguments.
//
// A policy file holds named profiles. Each profile is a list of rules; a rule names a tool (or a
// glob such as "k8s_*"), an effect (allow, ask or deny) and optional conditions on the arguments.
// Every rule that matches a call is collected and the most restrictive effect wins:
// deny beats ask, ask beats allow. A call that no rule matches gets the default effect, which is
// deny unless the file says otherwise. The evaluator is pure: no I/O, no clock, no globals.
package policy

import (
	"errors"
	"fmt"
	"os"
	"path"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Effect is the outcome of a policy decision.
type Effect string

const (
	Allow Effect = "allow"
	Ask   Effect = "ask"
	Deny  Effect = "deny"
	// Conditional is only reported by Explain, never returned by Evaluate.
	Conditional Effect = "conditional"
)

// rank orders effects from least to most restrictive.
func (e Effect) rank() int {
	switch e {
	case Allow:
		return 0
	case Ask:
		return 1
	default:
		return 2
	}
}

func (e Effect) valid() bool { return e == Allow || e == Ask || e == Deny }

// Condition constrains one argument. All set fields must hold for the condition to match.
type Condition struct {
	In    []string `yaml:"in,omitempty" json:"in,omitempty"`
	NotIn []string `yaml:"not_in,omitempty" json:"not_in,omitempty"`
	Glob  []string `yaml:"glob,omitempty" json:"glob,omitempty"`
	Max   *float64 `yaml:"max,omitempty" json:"max,omitempty"`
	Min   *float64 `yaml:"min,omitempty" json:"min,omitempty"`
	// Equals matches booleans and other scalars by their string form, for example dry_run: true.
	Equals *string `yaml:"equals,omitempty" json:"equals,omitempty"`
}

// Rule is one line of a profile.
type Rule struct {
	Tool   string               `yaml:"tool" json:"tool"`
	Effect Effect               `yaml:"effect" json:"effect"`
	When   map[string]Condition `yaml:"when,omitempty" json:"when,omitempty"`
	Reason string               `yaml:"reason,omitempty" json:"reason,omitempty"`
}

// Profile is a named rule set. Extends lists profiles whose rules are added to this one.
type Profile struct {
	Description string   `yaml:"description,omitempty" json:"description,omitempty"`
	Extends     []string `yaml:"extends,omitempty" json:"extends,omitempty"`
	Rules       []Rule   `yaml:"rules" json:"rules"`
}

// Policy is a parsed and validated policy file.
type Policy struct {
	Version  int                `yaml:"version" json:"version"`
	Default  Effect             `yaml:"default,omitempty" json:"default,omitempty"`
	Profiles map[string]Profile `yaml:"profiles" json:"profiles"`

	// resolved holds each profile's own rules followed by those of the profiles it extends.
	resolved map[string][]Rule
}

// Decision explains an evaluation. Rule is the index-free description of the deciding rule, so it
// can be shown to the agent and written to the audit log.
type Decision struct {
	Effect Effect `json:"effect"`
	Rule   string `json:"rule"`
	Reason string `json:"reason,omitempty"`
}

// Load reads and validates a policy file. knownTools, when not empty, is the set of tool names
// the gateway serves; a rule naming a tool outside it (and matching no tool as a glob) is an
// error, so a typo cannot silently leave a tool unguarded or unusable.
func Load(file string, knownTools []string) (*Policy, error) {
	data, err := os.ReadFile(file) // #nosec G304 -- operator-supplied config path
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	return Parse(data, knownTools)
}

// Parse validates policy YAML. Unknown fields are rejected.
func Parse(data []byte, knownTools []string) (*Policy, error) {
	var p Policy
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	if err := p.validate(knownTools); err != nil {
		return nil, err
	}
	return &p, nil
}

func (p *Policy) validate(knownTools []string) error {
	var errs []error
	if p.Version != 1 {
		errs = append(errs, fmt.Errorf("version: want 1, got %d", p.Version))
	}
	if p.Default == "" {
		p.Default = Deny
	}
	if !p.Default.valid() {
		errs = append(errs, fmt.Errorf("default: %q is not allow, ask or deny", p.Default))
	}
	if len(p.Profiles) == 0 {
		errs = append(errs, errors.New("profiles: at least one profile is required"))
	}
	for name, prof := range p.Profiles {
		for _, parent := range prof.Extends {
			if _, ok := p.Profiles[parent]; !ok {
				errs = append(errs, fmt.Errorf("profile %s: extends unknown profile %q", name, parent))
			}
		}
		for i, r := range prof.Rules {
			where := fmt.Sprintf("profile %s rule %d", name, i+1)
			if r.Tool == "" {
				errs = append(errs, fmt.Errorf("%s: tool is required", where))
				continue
			}
			if _, err := path.Match(r.Tool, ""); err != nil {
				errs = append(errs, fmt.Errorf("%s: bad tool pattern %q", where, r.Tool))
			}
			if !r.Effect.valid() {
				errs = append(errs, fmt.Errorf("%s: effect %q is not allow, ask or deny", where, r.Effect))
			}
			if len(knownTools) > 0 && !slices.ContainsFunc(knownTools, func(t string) bool { return toolMatches(r.Tool, t) }) {
				errs = append(errs, fmt.Errorf("%s: tool %q matches no tool this gateway serves", where, r.Tool))
			}
			for arg, c := range r.When {
				for _, g := range c.Glob {
					if _, err := path.Match(g, ""); err != nil {
						errs = append(errs, fmt.Errorf("%s: argument %s: bad glob %q", where, arg, g))
					}
				}
				if c.In == nil && c.NotIn == nil && c.Glob == nil && c.Max == nil && c.Min == nil && c.Equals == nil {
					errs = append(errs, fmt.Errorf("%s: argument %s: empty condition", where, arg))
				}
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("invalid policy: %w", errors.Join(errs...))
	}

	p.resolved = make(map[string][]Rule, len(p.Profiles))
	for name := range p.Profiles {
		rules, err := p.resolve(name, nil)
		if err != nil {
			return fmt.Errorf("invalid policy: %w", err)
		}
		p.resolved[name] = rules
	}
	return nil
}

func (p *Policy) resolve(name string, stack []string) ([]Rule, error) {
	if slices.Contains(stack, name) {
		return nil, fmt.Errorf("profile %s: extends cycle %s", name, strings.Join(append(stack, name), " -> "))
	}
	prof := p.Profiles[name]
	rules := slices.Clone(prof.Rules)
	for _, parent := range prof.Extends {
		inherited, err := p.resolve(parent, append(stack, name))
		if err != nil {
			return nil, err
		}
		rules = append(rules, inherited...)
	}
	return rules, nil
}

// HasProfile reports whether the policy defines the named profile.
func (p *Policy) HasProfile(name string) bool {
	_, ok := p.resolved[name]
	return ok
}

// Evaluate decides a call. args holds the tool's arguments after defaults were applied, as
// decoded JSON (strings, float64 numbers, bools). An unknown profile is denied.
func (p *Policy) Evaluate(profile, tool string, args map[string]any) Decision {
	rules, ok := p.resolved[profile]
	if !ok {
		return Decision{Effect: Deny, Rule: "unknown-profile", Reason: fmt.Sprintf("profile %q is not defined", profile)}
	}
	var best *Rule
	for i := range rules {
		r := &rules[i]
		if !toolMatches(r.Tool, tool) || !conditionsHold(r.When, args) {
			continue
		}
		if best == nil || r.Effect.rank() > best.Effect.rank() {
			best = r
		}
	}
	if best == nil {
		return Decision{Effect: p.Default, Rule: "default", Reason: "no rule matches this call"}
	}
	return Decision{Effect: best.Effect, Rule: describe(best), Reason: best.Reason}
}

// Explain returns the effect each tool gets for a profile from its unconditional rules, or
// "conditional" when rules with argument conditions can change that answer. It powers the
// gateway_policy tool, so an agent can plan without probing.
func (p *Policy) Explain(profile string, tools []string) map[string]Effect {
	out := make(map[string]Effect, len(tools))
	for _, t := range tools {
		eff, matched := p.Default, false
		var condEffects []Effect
		for _, r := range p.resolved[profile] {
			if !toolMatches(r.Tool, t) {
				continue
			}
			if len(r.When) > 0 {
				condEffects = append(condEffects, r.Effect)
				continue
			}
			if !matched || r.Effect.rank() > eff.rank() {
				eff, matched = r.Effect, true
			}
		}
		// An unconditional deny cannot be loosened; anything else can be changed by a condition.
		if !(matched && eff == Deny) && slices.ContainsFunc(condEffects, func(e Effect) bool { return e != eff }) {
			eff = Conditional
		}
		out[t] = eff
	}
	return out
}

func toolMatches(pattern, tool string) bool {
	ok, err := path.Match(pattern, tool)
	return err == nil && ok
}

func conditionsHold(when map[string]Condition, args map[string]any) bool {
	for arg, c := range when {
		v, present := args[arg]
		if !present || !c.holds(v) {
			return false
		}
	}
	return true
}

func (c Condition) holds(v any) bool {
	s := scalarString(v)
	if c.In != nil && !slices.Contains(c.In, s) {
		return false
	}
	if c.NotIn != nil && slices.Contains(c.NotIn, s) {
		return false
	}
	if c.Glob != nil && !slices.ContainsFunc(c.Glob, func(g string) bool { ok, _ := path.Match(g, s); return ok }) {
		return false
	}
	if c.Equals != nil && *c.Equals != s {
		return false
	}
	if c.Max != nil || c.Min != nil {
		n, ok := v.(float64)
		if !ok {
			return false
		}
		if c.Max != nil && n > *c.Max {
			return false
		}
		if c.Min != nil && n < *c.Min {
			return false
		}
	}
	return true
}

func scalarString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case float64:
		return strings.TrimSuffix(strings.TrimRight(fmt.Sprintf("%f", t), "0"), ".")
	case nil:
		return ""
	default:
		return fmt.Sprint(t)
	}
}

func describe(r *Rule) string {
	if len(r.When) == 0 {
		return fmt.Sprintf("%s %s", r.Effect, r.Tool)
	}
	keys := make([]string, 0, len(r.When))
	for k := range r.When {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return fmt.Sprintf("%s %s when %s", r.Effect, r.Tool, strings.Join(keys, ","))
}
