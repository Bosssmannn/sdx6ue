// docker-bake.hcl
// Builds recipe-api for both amd64 and arm64 in one command:
//   docker buildx bake --push

group "default" {
  targets = ["recipe-api"]
}

target "recipe-api" {
  context    = "."
  dockerfile = "Dockerfile"
  platforms  = ["linux/amd64", "linux/arm64"]
  tags       = ["recipe-api:latest"]
}
