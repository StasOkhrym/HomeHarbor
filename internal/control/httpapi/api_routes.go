package httpapi

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

func (s *Server) registerAPI(api chi.Router) {
	api.Use(limitRequestBody)
	api.Use(s.apiLimiter.Middleware(s.clientKey))
	if s.browserAPI != nil {
		api.Mount("/auth", s.authLimiter.Middleware(s.clientKey)(s.browserAPI))
	}
	s.registerAdminAPI(api)
	s.registerDeviceAPI(api)
	s.registerServiceAPI(api)
	s.registerInviteAPI(api)
	s.registerCoordinationAPI(api)
	if s.relayIssuer != nil {
		// Slash and bare collection paths are compatibility aliases: admission
		// limits and authenticated peer checks must be identical on both paths.
		handler := s.deviceLimiter.Middleware(s.clientKey)(http.HandlerFunc(s.issueRelaySession))
		api.Post("/relay-sessions", handler.ServeHTTP)
		api.Post("/relay-sessions/", handler.ServeHTTP)
	}
}

func (s *Server) registerAdminAPI(api chi.Router) {
	api.Route("/admin", func(admin chi.Router) {
		admin.Use(s.requireAdmin)
		admin.Post("/enrollment-tokens", s.issueToken)
		admin.Get("/devices", s.listDevices)
		if s.audit != nil {
			admin.Get("/audit", s.listAudit)
		}
		if s.routes != nil {
			admin.Get("/routes", s.listRoutes)
		}
		if s.services != nil {
			admin.Get("/services", s.listServices)
		}
		if s.profiles != nil {
			admin.Get("/access-profiles", s.listProfiles)
		}
	})
	api.Group(func(admin chi.Router) {
		admin.Use(s.requireAdmin)
		admin.Post("/enrollment-tokens", s.issueToken)
		if s.routes != nil {
			admin.Get("/routes", s.listRoutes)
			admin.Post("/routes", s.advertiseRoute)
			admin.Post("/routes/{id}/approve", s.approveRoute)
			admin.Post("/routes/{id}/reject", s.rejectRoute)
		}
		if s.policy != nil {
			admin.Get("/policy", s.latestPolicy)
			admin.Put("/policy", s.replacePolicy)
		}
		if s.profiles != nil {
			admin.Get("/access-profiles", s.listProfiles)
			admin.Post("/access-profiles", s.createProfile)
		}
	})
}

func (s *Server) registerDeviceAPI(api chi.Router) {
	api.With(s.deviceLimiter.Middleware(s.clientKey)).Post("/enroll", s.enroll)
	api.With(s.requireAdmin).Get("/devices", s.listDevices)
	api.Route("/devices", func(device chi.Router) {
		device.Group(func(admin chi.Router) {
			admin.Use(s.requireAdmin)
			admin.Get("/", s.listDevices)
			admin.Delete("/{id}", s.revokeDevice)
		})
		// Rotation authenticates the existing DB-backed device credential. It
		// must not inherit browser auth or Redis-dependent onboarding quotas.
		device.Post("/credentials/rotate", s.rotateCredential)
		if s.recovery != nil {
			device.With(s.deviceLimiter.Middleware(s.clientKey)).
				Post("/credentials/challenge", s.credentialChallenge)
			device.With(s.deviceLimiter.Middleware(s.clientKey)).
				Post("/credentials/recovery", s.recoverCredential)
		}
	})
}

func (s *Server) registerServiceAPI(api chi.Router) {
	if s.services == nil {
		return
	}

	api.With(s.requireAdmin).Get("/services", s.listServices)
	api.With(s.requireAdmin).Post("/services", s.createService)
	api.Route("/services", func(service chi.Router) {
		service.With(s.requireDevice).Get("/available", s.listAvailableServices)
		service.Group(func(admin chi.Router) {
			admin.Use(s.requireAdmin)
			admin.Get("/", s.listServices)
			admin.Post("/", s.createService)
		})
	})
}

func (s *Server) registerInviteAPI(api chi.Router) {
	api.Route("/invites", func(invites chi.Router) {
		invites.Use(s.deviceLimiter.Middleware(s.clientKey))
		if s.activationChallenge != nil {
			invites.Post("/{id}/challenge", s.activationChallenge)
		}

		if s.activationClaim != nil {
			invites.Post("/{id}/claim", s.activationClaim)
		}

		if s.invites != nil {
			invites.Post("/proof", s.submitInviteProof)
			invites.Get("/{id}", s.getInvite)
			invites.Post("/{id}/approval", s.approveInvite)
		}
	})
}

func (s *Server) registerCoordinationAPI(api chi.Router) {
	if s.coordination != nil {
		api.Get("/coordination", s.coordination.ServeHTTP)
	}

	api.Route("/coordination", func(coordination chi.Router) {
		if s.coordination != nil {
			coordination.Get("/", s.coordination.ServeHTTP)
		}

		if s.snapshotHistory != nil {
			coordination.Get("/snapshots", s.snapshotHistory.ServeHTTP)
		}

		if s.snapshots == nil {
			return
		}

		coordination.With(s.requireAdmin).Get("/snapshot", s.latestSnapshot)
		coordination.Group(func(companion chi.Router) {
			companion.Use(s.deviceLimiter.Middleware(s.clientKey))
			companion.Post("/snapshots", s.publishSnapshot)
			if s.companionChallenges != nil {
				companion.Get("/snapshot/companion-challenge", s.issueCompanionChallenge)
				companion.Get("/snapshot/companion", s.companionSnapshot)
			}
		})
	})
}

func (s *Server) registerBrowserAdmin(admin chi.Router) {
	admin.Use(limitRequestBody)
	admin.Use(s.apiLimiter.Middleware(s.clientKey))
	if s.loginPage != nil {
		admin.Handle("/login", s.loginPage)
	}
	admin.Group(func(protected chi.Router) {
		protected.Use(s.requireAdmin)
		protected.Get("/", s.adminDashboard)
		for _, page := range []string{"setup", "devices", "services", "access", "network", "invites", "activity", "security"} {
			protected.Get("/"+page, s.adminView(page))
		}
		protected.Get("/activity/fragment", s.adminActivityFragment)
		protected.Get("/devices/{id}", s.adminView("devices"))
		protected.Post("/enrollment-tokens", s.issueEnrollmentTokenForm)
		protected.Post("/devices/{id}/revoke", s.revokeDeviceForm)
		if s.routes != nil {
			protected.Post("/routes", s.createRouteForm)
			protected.Post("/routes/approve", s.approveRouteForm)
			protected.Post("/routes/reject", s.rejectRouteForm)
			protected.Post("/routes/{id}/approve", s.approveRouteForm)
			protected.Post("/routes/{id}/reject", s.rejectRouteForm)
		}
		protected.Post("/services", s.createServiceForm)
		protected.Post("/access-profiles", s.createProfileForm)
		protected.Post("/policy", s.replacePolicyForm)
		protected.Post("/policy/preview", s.previewPolicyForm)
	})
}
