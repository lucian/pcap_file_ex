[
  # Mix.Task false positives - Mix.Task behavior and Mix.shell/0 unavailable at compile-time
  ~r/lib\/mix\/tasks\/test\/fixtures\.ex/,
  {"lib/mix/tasks/test/fixtures.ex", :callback_info_missing, 1},
  {"lib/mix/tasks/test/fixtures.ex", :unknown_function, 57},
  {"lib/mix/tasks/test/fixtures.ex", :unknown_function, 133},

  # Test support files - backup safety net (shouldn't be analyzed with paths config)
  ~r/test\/support/,

  # StreamData warnings - backup safety net (shouldn't appear if test files excluded)
  ~r/StreamData/
]
