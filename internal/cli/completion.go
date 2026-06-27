package cli

import (
	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/spf13/cobra"
)

// completion.go is the `daxib completion bash|zsh|fish|powershell` command. The
// root DISABLES Cobra's auto-registered completion command (CompletionOptions.
// DisableDefaultCmd) so the documented surface stays exact; this is the explicit,
// non-hidden replacement that emits the SAME script Cobra generates from the real
// command tree (so it never drifts from the actual flags/subcommands).
//
// It opens no service and ignores --json (a completion script is shell source, not
// data). Exit codes: 0 on success; 2 (usage) on an unknown/missing shell argument
// (enforced by ValidArgs + OnlyValidArgs, which surface as a Cobra usage error the
// central funnel projects to exit 2).
func newCompletionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate a shell completion script",
		Long: "Output a completion script for the given shell, generated from the live\n" +
			"command tree. Source it from your shell rc.\n\nExamples:\n" +
			"  daxib completion bash > /etc/bash_completion.d/daxib\n" +
			"  daxib completion zsh  > \"${fpath[1]}/_daxib\"\n" +
			"  daxib completion fish > ~/.config/fish/completions/daxib.fish\n" +
			"  daxib completion powershell > daxib.ps1",
		ValidArgs: []string{"bash", "zsh", "fish", "powershell"},
		Args:      cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		// Not hidden, and exempt from completion-of-the-completion noise.
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			root := cmd.Root()
			switch args[0] {
			case "bash":
				return wrapGenCompletion(root.GenBashCompletionV2(out, true))
			case "zsh":
				return wrapGenCompletion(root.GenZshCompletion(out))
			case "fish":
				return wrapGenCompletion(root.GenFishCompletion(out, true))
			case "powershell":
				return wrapGenCompletion(root.GenPowerShellCompletionWithDesc(out))
			default:
				// Unreachable given ValidArgs, but kept explicit for honesty.
				return domain.Newf("usage.completion.unknown_shell", "unknown shell %q (want bash|zsh|fish|powershell)", args[0])
			}
		},
	}
	return cmd
}

// wrapGenCompletion turns a generator's raw I/O error (a failure writing the
// script) into a typed internal error so it funnels through the registry like
// every other command failure.
func wrapGenCompletion(err error) error {
	if err == nil {
		return nil
	}
	return domain.Wrap("internal", "failed to write completion script", err)
}
