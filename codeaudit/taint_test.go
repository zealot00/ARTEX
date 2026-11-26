package codeaudit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExpandedDefectRulesAndTaintFlows(t *testing.T) {
	dir := t.TempDir()

	javaSrc := `package com.example;
import javax.xml.parsers.DocumentBuilderFactory;
import org.springframework.beans.BeanUtils;

public class OrderController {
    public void importXml(@RequestBody String xml, HttpServletResponse resp, @RequestParam String next) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        resp.sendRedirect(next);
    }
    public void updateUser(@RequestBody UserDTO dto, UserEntity entity) {
        BeanUtils.copyProperties(dto, entity);
    }
}
`
	jsSrc := `export function renderBanner(req, res) {
  const html = req.query.msg;
  document.getElementById("out").innerHTML = html;
}
`
	if err := os.WriteFile(filepath.Join(dir, "OrderController.java"), []byte(javaSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "banner.js"), []byte(jsSrc), 0o644); err != nil {
		t.Fatal(err)
	}

	sinks, err := ScanSinks(dir, nil, 50)
	if err != nil {
		t.Fatalf("ScanSinks failed: %v", err)
	}
	wantRules := map[string]bool{
		"java-xml-parser-xxe":     false,
		"unvalidated-redirect":    false,
		"mass-assignment-binding": false,
		"unsafe-html-render":      false,
	}
	for _, s := range sinks {
		if _, ok := wantRules[s.Rule]; ok {
			wantRules[s.Rule] = true
		}
	}
	for rule, found := range wantRules {
		if !found {
			t.Errorf("expected sink rule %q to match, got %+v", rule, sinks)
		}
	}

	flows, err := TraceTaintFlows(dir, nil, 50)
	if err != nil {
		t.Fatalf("TraceTaintFlows failed: %v", err)
	}
	if len(flows) < 3 {
		t.Fatalf("expected >=3 intra-file source-to-sink flows, got %+v", flows)
	}
	foundHighConf := false
	for _, f := range flows {
		if f.Confidence == "high" && !f.SanitizerSeen && f.SourceLine > 0 && f.SinkLine >= f.SourceLine {
			foundHighConf = true
		}
	}
	if !foundHighConf {
		t.Fatalf("expected at least one high-confidence unsanitized taint flow, got %+v", flows)
	}
}
