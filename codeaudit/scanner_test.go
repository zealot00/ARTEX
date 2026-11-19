package codeaudit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCodeAuditEngineEndToEnd(t *testing.T) {
	tmp := t.TempDir()

	// 1) Java Spring controller with MyBatis ${}, Fastjson, pre-auth ticket leak, and permitAll.
	javaDir := filepath.Join(tmp, "src", "main", "java", "com", "corp")
	if err := os.MkdirAll(javaDir, 0o755); err != nil {
		t.Fatal(err)
	}
	javaCode := `package com.corp;
@RestController
public class AuthController {
    @PostMapping("/api/sms/send")
    public Map<String, Object> sendSms(String phone) {
        String ticket = createTicket(phone);
        return Map.of("status", "ok", "ticket", ticket);
    }

    @GetMapping("/api/user")
    public Object findUser(String raw) {
        Object obj = JSON.parseObject(raw);
        return querySql("SELECT * FROM users WHERE name = '" + raw + "'");
    }

    public void configure(HttpSecurity http) {
        http.authorizeRequests().antMatchers("/api/sms/**").permitAll();
    }
}
`
	if err := os.WriteFile(filepath.Join(javaDir, "AuthController.java"), []byte(javaCode), 0o644); err != nil {
		t.Fatal(err)
	}

	// 2) pom.xml with fastjson & log4j-core.
	pom := `<project><dependencies>
  <dependency><artifactId>fastjson</artifactId><version>1.2.68</version></dependency>
  <dependency><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency>
</dependencies></project>`
	if err := os.WriteFile(filepath.Join(tmp, "pom.xml"), []byte(pom), 0o644); err != nil {
		t.Fatal(err)
	}

	// SafeResolveDir must block path traversal outside workspace.
	if _, err := SafeResolveDir(tmp, "../../etc"); err == nil {
		t.Fatal("expected SafeResolveDir to reject traversal")
	}
	resolved, err := SafeResolveDir(tmp, ".")
	if err != nil {
		t.Fatalf("SafeResolveDir(.): %v", err)
	}

	// MapEntrypoints
	entries, err := MapEntrypoints(resolved, 50)
	if err != nil {
		t.Fatalf("MapEntrypoints: %v", err)
	}
	if len(entries) < 3 {
		t.Fatalf("expected >= 3 entrypoint/whitelist hits, got %+v", entries)
	}

	// ScanSinks
	sinks, err := ScanSinks(resolved, nil, 50)
	if err != nil {
		t.Fatalf("ScanSinks: %v", err)
	}
	foundRules := map[string]bool{}
	for _, s := range sinks {
		foundRules[s.Rule] = true
	}
	for _, want := range []string{"preauth-ticket-otp-leak", "java-deser-fastjson", "sql-string-concat"} {
		if !foundRules[want] {
			t.Errorf("ScanSinks missed rule %q; got %+v", want, sinks)
		}
	}

	// TraceSymbol
	refs, err := TraceSymbol(resolved, "createTicket", 20)
	if err != nil || len(refs) == 0 {
		t.Fatalf("TraceSymbol(createTicket): err=%v refs=%+v", err, refs)
	}

	// AuditDependencies
	advs, manifests, err := AuditDependencies(resolved)
	if err != nil {
		t.Fatalf("AuditDependencies: %v", err)
	}
	if len(manifests) != 1 || len(advs) < 2 {
		t.Fatalf("expected 1 manifest and >=2 advisories, got manifests=%v advs=%+v", manifests, advs)
	}
	var gotFastjson bool
	for _, a := range advs {
		if a.Package == "fastjson" && strings.Contains(a.Version, "1.2.68") {
			gotFastjson = true
		}
	}
	if !gotFastjson {
		t.Fatalf("expected fastjson 1.2.68 advisory, got %+v", advs)
	}
}
