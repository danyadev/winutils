{
  "targets": [{
    "target_name": "winutils",
    "sources": ["index.cc"],

    "conditions": [
      [
        "OS=='win'",
        {
          "defines": ["UNICODE=1"]
        }
      ]
    ]
  }]
}
