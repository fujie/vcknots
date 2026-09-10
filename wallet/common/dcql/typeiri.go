package dcql

import "regexp"

// Expansion of W3C Verifiable Credential types to IRIs.
//
// DCQL matches type_values against "the fully expanded types (IRIs) that the
// Verifier accepts in a Presentation, after applying the @context to the
// Verifiable Credential" (OpenID4VP 1.0 Appendix B.1.1). A type entry is a term
// the credential's @context maps to an IRI, so VerifiableCredential under the
// standard context is really
// https://www.w3.org/2018/credentials#VerifiableCredential.
//
// Appendix B.1.1 also says what to do with a term no context defines: it
// "remains unchanged, i.e., remains a relative IRI after JSON-LD processing.
// For this reason, JSON-LD processing MAY be skipped in such cases and the
// relative IRI is considered to be the fully expanded type". It allows
// "alternative mechanisms to obtain the fully expanded types, as long as the
// results are equivalent to those produced by JSON-LD processing".
//
// That is what this file is: a table of the contexts this wallet accepts,
// rather than a JSON-LD processor. A term the table does not cover is returned
// unchanged, which is what the specification prescribes for a term outside
// every @context.

const (
	// credentialsVocabulary is where the W3C Verifiable Credentials contexts
	// define their terms.
	credentialsVocabulary = "https://www.w3.org/2018/credentials#"
	// examplesVocabulary is the W3C example context's vocabulary, used
	// throughout the specifications.
	examplesVocabulary = "https://example.org/examples#"
)

// contextTerms maps an @context URL to the type terms it defines.
//
// Only type terms are listed: a claims path pointer addresses claims by their
// JSON member name and never needs expansion (Appendix B.1.2).
var contextTerms = map[string]map[string]string{
	"https://www.w3.org/2018/credentials/v1": {
		"VerifiableCredential":   credentialsVocabulary + "VerifiableCredential",
		"VerifiablePresentation": credentialsVocabulary + "VerifiablePresentation",
	},
	"https://www.w3.org/ns/credentials/v2": {
		"VerifiableCredential":          credentialsVocabulary + "VerifiableCredential",
		"VerifiablePresentation":        credentialsVocabulary + "VerifiablePresentation",
		"EnvelopedVerifiableCredential": credentialsVocabulary + "EnvelopedVerifiableCredential",
	},
	"https://www.w3.org/2018/credentials/examples/v1": {
		"UniversityDegreeCredential": examplesVocabulary + "UniversityDegreeCredential",
		"AlumniCredential":           examplesVocabulary + "AlumniCredential",
		"BachelorDegree":             examplesVocabulary + "BachelorDegree",
	},
}

// absoluteIRI recognises a value that is already expanded, which is left alone.
var absoluteIRI = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*:`)

// ExpandCredentialType expands one type against the contexts a Credential
// declares. The contexts are consulted in order, as JSON-LD does, so a later
// context may define a term an earlier one did not.
func ExpandCredentialType(credentialType string, contexts []string) string {
	if absoluteIRI.MatchString(credentialType) {
		return credentialType
	}
	for _, context := range contexts {
		if iri, ok := contextTerms[context][credentialType]; ok {
			return iri
		}
	}
	// No @context defines it, so it is already its own fully expanded type.
	return credentialType
}

// CredentialContexts reads the @context of a Credential, tolerating the
// single-string form.
func CredentialContexts(credential map[string]any) []string {
	switch raw := credential["@context"].(type) {
	case string:
		return []string{raw}
	case []any:
		contexts := make([]string, 0, len(raw))
		for _, entry := range raw {
			if context, ok := entry.(string); ok {
				contexts = append(contexts, context)
			}
		}
		return contexts
	default:
		return nil
	}
}

// ExpandCredentialTypes returns the fully expanded types of a Credential, ready
// to be compared with the type_values of a Credential Query.
func ExpandCredentialTypes(types []string, contexts []string) []string {
	expanded := make([]string, 0, len(types))
	for _, credentialType := range types {
		expanded = append(expanded, ExpandCredentialType(credentialType, contexts))
	}
	return expanded
}
