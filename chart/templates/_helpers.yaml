{{-  define "image" -}}
  {{- if hasPrefix "sha256:" .tag }}
  {{- printf "%s@%s" .repository .tag }}
  {{- else }}
  {{- printf "%s:%s" .repository .tag }}
  {{- end }}
{{- end }}