package triage

import (
	"context"
	"time"

	"github.com/fedorovmv/izyan/internal/llm"
)

// chatWithTransientRetry calls the provider with up to chatMaxAttempts
// attempts: transient failures (transport errors, HTTP 429 and HTTP 5xx)
// retry after chatBackoff, while every other error is terminal on the first
// attempt. sleep injects the backoff wait (nil means time.Sleep-based wait);
// it stays bounded by chatBackoff and aborts when the context ends.
// Intake extraction, ref selection and the bounded agent loop share this
// one retry policy so a transient gateway error can never skip or unbound
// a Stage 0 LLM call.
func chatWithTransientRetry(
	ctx context.Context,
	sleep func(context.Context, time.Duration) error,
	client ChatClient,
	role llm.ModelRole,
	system string,
	messages []llm.ChatMessage,
	defs []llm.ToolDefinition,
) (llm.ChatMessage, string, error) {
	for attempt := 0; ; attempt++ {
		msg, finish, err := client.Chat(ctx, role, system, messages, defs)
		if err == nil {
			return msg, finish, nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return llm.ChatMessage{}, "", ctxErr
		}
		if attempt >= chatMaxAttempts-1 || !isTransientLLMError(err) {
			return llm.ChatMessage{}, "", err
		}
		if werr := chatBackoffWait(ctx, sleep, chatBackoff[attempt]); werr != nil {
			return llm.ChatMessage{}, "", werr
		}
	}
}

// chatBackoffWait blocks for the backoff delay, aborting early when the
// context ends; the wake-up reason is the context error, never a silent
// oversleep.
func chatBackoffWait(ctx context.Context, sleep func(context.Context, time.Duration) error, d time.Duration) error {
	if sleep != nil {
		return sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
