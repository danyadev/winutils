{
  "targets": [
    {
      "target_name": "winutils",
      "sources": [ "index.cc" ],
    
      'conditions': [
        [ 'OS=="win"', {
          'defines': [
            'UNICODE=1',
            '_UNICODE=1',
            '_SQLNCLI_ODBC_',
          ],
          'libraries': [
            'odbc32.lib'
          ],
          }
        ]
      ]
    }
  ]
}
