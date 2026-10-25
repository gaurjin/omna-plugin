cask "omna" do
  version "0.6.2"
  sha256 "19e7a44651c56af66ee43837416ae3118a30a3f38444dcde7edea3a7af891cc1"

  url "https://github.com/gaurjin/omna-plugin/releases/download/v#{version}/omna-#{version}-macos-arm64.zip",
      verified: "github.com/gaurjin/omna-plugin/"
  name "Omna"
  desc "Masks secrets and PII before your prompt leaves the machine"
  homepage "https://omna.dev/"

  # Apple Silicon only, for the same reason the engine has no source
  # distribution: it ships as an architecture-specific compiled wheel.
  depends_on arch: :arm64
  depends_on macos: ">= :ventura"

  binary "omna/omna"

  caveats <<~EOS
    Wire up your tools (Claude Code, aider, Codex CLI, VS Code, Continue) and,
    on a Mac, the system proxy + local certificate:

      omna init
      omna start -d
      omna status

    "omna init" asks for your password once, and prints every command it will
    run as administrator before running it.

    To remove Omna completely, run this FIRST:

      omna uninstall

    It un-wires your tools, removes the certificate and system proxy, and
    deletes the encryption keys from your Keychain. Homebrew cannot reach the
    Keychain, so "brew uninstall" alone would leave those two keys behind.
  EOS

  # Everything Omna writes on disk lives in one directory. Verified 2026-09-20:
  # `brew uninstall --zap` does remove it — but it canNOT remove the two
  # Keychain items (the registry key and the receipts key), because a zap
  # stanza only trashes files. Hence the caveat above telling people to run
  # `omna uninstall` first, which does.
  zap trash: [
    "~/.omna",
  ]
end
