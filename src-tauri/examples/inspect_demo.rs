use argus_lib::scanner::scan_file;
use std::path::PathBuf;
fn main() {
  let files = [
    "/Users/web/code/test-repos/pinia/package.json",
    "/Users/web/code/test-repos/nitro/test/fixture/server/routes/icon.png.ts",
    "/Users/web/code/test-repos/rollup/package.json",
    "/Users/web/code/test-repos/langchainjs/libs/langchain-core/src/messages/block_translators/tests/google_vertexai.test.ts",
    "/Users/web/code/test-repos/langchainjs/libs/providers/langchain-anthropic/src/tests/chat_models-web_search.test.ts",
    "/Users/web/code/test-repos/langchainjs/libs/providers/langchain-aws/src/tests/chat_models.test.ts",
    "/Users/web/code/test-repos/langchainjs/libs/providers/langchain-aws/src/chat_models.ts",
  ];
  for f in files {
    let p = PathBuf::from(f);
    if let Ok(Some(d)) = scan_file(&p) {
      println!("\n{:?}  {}", d.top_severity, f);
      for h in &d.hits {
        println!("  {} {:?}/{:?} - {}", h.rule_id, h.severity, h.confidence, h.title);
        println!("    matched: {:?}", h.matched.as_deref().unwrap_or("").chars().take(140).collect::<String>());
      }
    }
  }
}
