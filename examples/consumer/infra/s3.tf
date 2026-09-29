# Artifact bucket for webhook payloads — private, encrypted, versioned.

resource "aws_s3_bucket" "webhooks" {
  bucket = "company-webhook-payloads-private"
}

resource "aws_s3_bucket_public_access_block" "webhooks" {
  bucket                  = aws_s3_bucket.webhooks.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "webhooks" {
  bucket = aws_s3_bucket.webhooks.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "webhooks" {
  bucket = aws_s3_bucket.webhooks.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_ownership_controls" "webhooks" {
  bucket = aws_s3_bucket.webhooks.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_policy" "webhooks_tls" {
  bucket = aws_s3_bucket.webhooks.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.webhooks.arn,
          "${aws_s3_bucket.webhooks.arn}/*",
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })
}
