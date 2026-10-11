# Bake definition: multi-arch static image (task 45).
# Usage: `docker buildx bake` (both arches) or
#   `docker buildx bake image --set image.platform=linux/amd64` (one arch).
variable "TAG" {
  default = "latest"
}

# Comma-separated tag list. Must be an env var, not `--set image.tags=`: bake
# parses a `--set` value as one string, so a comma list becomes a single
# invalid tag instead of several.
variable "IMAGE_TAGS" {
  default = ""
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
  tags       = IMAGE_TAGS != "" ? split(",", IMAGE_TAGS) : ["d-oauth-server:${TAG}"]
  args = {
    SOURCE_DATE_EPOCH = "${SOURCE_DATE_EPOCH}"
  }
}
