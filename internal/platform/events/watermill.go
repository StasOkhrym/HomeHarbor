package events

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ThreeDotsLabs/watermill"
	"github.com/ThreeDotsLabs/watermill/message"

	"github.com/sokhrym/go-tunnels/internal/control/devices"
)

type WatermillPublisher struct{ publisher message.Publisher }

func NewWatermillPublisher(publisher message.Publisher) *WatermillPublisher {
	return &WatermillPublisher{publisher: publisher}
}

func (p *WatermillPublisher) Publish(_ context.Context, event devices.Event) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	msg := message.NewMessage(watermill.NewUUID(), payload)
	if err = p.publisher.Publish(event.Type, msg); err != nil {
		return fmt.Errorf("publish %s: %w", event.Type, err)
	}
	return nil
}
