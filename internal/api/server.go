package api

import (
	"fmt"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
)

// Server wraps the Fiber HTTP server.
type Server struct {
	app  *fiber.App
	port int
}

// NewServer creates a new API server.
func NewServer(port int) *Server {
	app := fiber.New(fiber.Config{
		AppName:      "pentestswarm",
		ErrorHandler: errorHandler,
	})

	// Middleware
	app.Use(recover.New())
	app.Use(logger.New(logger.Config{
		Format: "${time} ${status} ${method} ${path} ${latency}\n",
	}))
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowHeaders: "Origin, Content-Type, Accept, X-API-Key",
	}))

	s := &Server{app: app, port: port}
	s.registerRoutes()

	return s
}

// Start begins serving HTTP requests.
func (s *Server) Start() error {
	return s.app.Listen(fmt.Sprintf(":%d", s.port))
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown() error {
	return s.app.Shutdown()
}

func (s *Server) registerRoutes() {
	api := s.app.Group("/api/v1")

	// Health
	api.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok", "service": "pentestswarm"})
	})

	// Campaigns
	api.Post("/campaigns", s.createCampaign)
	api.Get("/campaigns", s.listCampaigns)
	api.Get("/campaigns/:id", s.getCampaign)
	api.Post("/campaigns/:id/start", s.startCampaign)
	api.Post("/campaigns/:id/stop", s.stopCampaign)
	api.Get("/campaigns/:id/findings", s.getCampaignFindings)
	api.Get("/campaigns/:id/report", s.getCampaignReport)
	api.Get("/campaigns/:id/events", s.streamCampaignEvents)

	// Models
	api.Get("/models", s.listModels)

	// Stats
	api.Get("/stats", s.getStats)
}

// --- Handlers ---

func (s *Server) createCampaign(c *fiber.Ctx) error {
	// TODO: parse body, create campaign in DB
	return c.Status(201).JSON(fiber.Map{"id": "placeholder", "status": "planned"})
}

func (s *Server) listCampaigns(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{"data": []any{}, "meta": fiber.Map{"total": 0}})
}

func (s *Server) getCampaign(c *fiber.Ctx) error {
	id := c.Params("id")
	return c.JSON(fiber.Map{"id": id, "status": "not found"})
}

func (s *Server) startCampaign(c *fiber.Ctx) error {
	return c.Status(202).JSON(fiber.Map{"status": "starting"})
}

func (s *Server) stopCampaign(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{"status": "stopped"})
}

func (s *Server) getCampaignFindings(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{"data": []any{}})
}

func (s *Server) getCampaignReport(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{"status": "no report yet"})
}

func (s *Server) streamCampaignEvents(c *fiber.Ctx) error {
	// TODO: WebSocket upgrade
	return c.JSON(fiber.Map{"status": "websocket endpoint"})
}

func (s *Server) listModels(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{"models": []string{
		"ArmurAI/recon-agent-qwen2.5-7b",
		"ArmurAI/classifier-agent-mistral-7b",
		"ArmurAI/exploit-agent-deepseek-r1-8b",
		"ArmurAI/report-agent-llama3.1-8b",
	}})
}

func (s *Server) getStats(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"campaigns":        0,
		"active_campaigns": 0,
		"total_findings":   0,
		"critical":         0,
		"high":             0,
	})
}

// --- Error Handling ---

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func errorHandler(c *fiber.Ctx, err error) error {
	code := fiber.StatusInternalServerError
	if e, ok := err.(*fiber.Error); ok {
		code = e.Code
	}

	return c.Status(code).JSON(fiber.Map{
		"error": apiError{
			Code:    fmt.Sprintf("%d", code),
			Message: err.Error(),
		},
	})
}
