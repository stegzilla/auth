package project

import (
	"net/http"

	"github.com/gorilla/mux"

	"github.com/todanni/auth/storage"
)

type ProjectsService interface {
	CreateProjectHandler(w http.ResponseWriter, r *http.Request)
	GetProjectHandler(w http.ResponseWriter, r *http.Request)
	UpdateProjectHandler(w http.ResponseWriter, r *http.Request)
	ListProjectsHandler(w http.ResponseWriter, r *http.Request)
	DeleteProjectHandler(w http.ResponseWriter, r *http.Request)
}

func NewProjectService(router *mux.Router, projectStorage storage.ProjectStorage) ProjectsService {
	service := &projectService{
		router:         router,
		projectStorage: projectStorage,
	}
	service.routes()
	return service
}

type projectService struct {
	router         *mux.Router
	projectStorage storage.ProjectStorage
}

func (s *projectService) UpdateProjectHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Unimplemented", http.StatusMethodNotAllowed)
}

func (s *projectService) CreateProjectHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Unimplemented", http.StatusMethodNotAllowed)
}

func (s *projectService) GetProjectHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Unimplemented", http.StatusMethodNotAllowed)
}

func (s *projectService) ListProjectsHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Unimplemented", http.StatusMethodNotAllowed)
}

func (s *projectService) DeleteProjectHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Unimplemented", http.StatusMethodNotAllowed)
}
