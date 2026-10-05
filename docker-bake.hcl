# Bake definition: multi-arch static image (task 45).
# Usage: `docker buildx bake` (both arches) or
#   `docker buildx bake image --set image.platform=linux/amd64` (one arch).
variable "TAG" {
  default = "latest"
}

variable "SOURCE_DATE_EPOCH" {
  default = "0"
}

group "default" {
  targets = ["image"]
}

target "image" {
  dockerfile = "Dockerfile"
  context    = "."
  platforms  = ["linux/amd64", "linux/arm64"]
  tags       = ["d-oauth-server:${TAG}"]
  args = {
    SOURCE_DATE_EPOCH = "${SOURCE_DATE_EPOCH}"
  }
}
