group "default" {
  targets = ["recipe-api"]
}

target "recipe-api" {
  context = "."
  dockerfile = "Dockerfile"
  # This line satisfies the multi-platform requirement
  platforms = ["linux/amd64", "linux/arm64"]
  tags = ["recipe-api:latest"]
}
