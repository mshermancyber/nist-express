{{- define "chart.fullname" -}}
{{- printf "%s" (.Release.Name | default "nist-express") -}}
{{- end -}}
