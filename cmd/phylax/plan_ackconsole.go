package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/PurdueBlueTeam/phylax/internal/controller"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

func init() {
	register(command{name: "plan", summary: "plan tools: ack-console -data-dir D -plan P -node N -operator NAME", run: runPlan})
}

func runPlan(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] != "ack-console" {
		return errors.New("usage: phylax plan ack-console -data-dir DIR -plan ID -node ID -operator NAME")
	}
	fs := flag.NewFlagSet("plan ack-console", flag.ContinueOnError)
	dataDir := fs.String("data-dir", "", "controller data directory")
	planID := fs.String("plan", "", "plan id")
	node := fs.String("node", "", "node id of the palo.*/vyos.* node")
	operator := fs.String("operator", "", "name of the Network role operator who confirmed console access")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *dataDir == "" || *planID == "" || *node == "" || *operator == "" {
		return errors.New("-data-dir, -plan, -node and -operator are all required")
	}
	st, err := store.Open(ctx, filepath.Join(*dataDir, "phylax.db"))
	if err != nil {
		return err
	}
	defer st.Close()
	if err := controller.AckConsoleStored(ctx, st, *planID, *node, *operator); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "console access acknowledged for %s/%s by %s (recorded in the audit log)\n", *planID, *node, *operator)
	return nil
}
