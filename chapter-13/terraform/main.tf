terraform {
  required_version = ">= 1.5.0"
  required_providers {
    mongodbatlas = {
      source  = "mongodb/mongodbatlas"
      version = "~> 1.14.0"
    }
  }
}

variable "atlas_public_key" {
  type        = string
  description = "MongoDB Atlas Programmatic Public API Key"
  sensitive   = true
}

variable "atlas_private_key" {
  type        = string
  description = "MongoDB Atlas Programmatic Private API Key"
  sensitive   = true
}

variable "atlas_org_id" {
  type        = string
  description = "MongoDB Atlas Organization ID"
}

variable "project_name" {
  type        = string
  default     = "Threat-Intelligence-CTI"
}

variable "cluster_name" {
  type        = string
  default     = "cti-prod-cluster"
}

provider "mongodbatlas" {
  public_key  = var.atlas_public_key
  private_key = var.atlas_private_key
}

resource "mongodbatlas_project" "cti_project" {
  name   = var.project_name
  org_id = var.atlas_org_id
}

resource "mongodbatlas_cluster" "cti_cluster" {
  project_id   = mongodbatlas_project.cti_project.id
  name         = var.cluster_name
  cluster_type = "REPLICASET"
  replication_specs {
    num_shards = 1
    regions_config {
      region_name     = "US_EAST_1"
      electable_nodes = 3
      priority        = 7
      read_only_nodes = 0
    }
  }
  cloud_backup                 = true
  auto_scaling_disk_gb_enabled = true
  mongo_db_major_version       = "7.0"
  provider_name                = "AWS"
  provider_instance_size_name  = "M10"
}

output "connection_string" {
  value       = mongodbatlas_cluster.cti_cluster.connection_strings[0].standard_srv
  description = "Standard SRV connection string for application clients"
}
