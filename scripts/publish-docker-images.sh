# Publishing a Docker image to AWS Public ECR
# https://docs.google.com/document/d/1MRV9UuyaPHdC6oz9ZzknQjFm03UpORojDGd_tjzwYDg/edit?usp=sharing
#
# Set variables
IMAGE_NAME="my-app"
IMAGE_TAG="latest"
REGION="us-east-1"

# Authenticate Docker to public ECR
aws ecr-public get-login-password --region $REGION | docker login --username AWS --password-stdin public.ecr.aws

# Create public repository (ignore error if it already exists)
aws ecr-public create-repository --repository-name $IMAGE_NAME --region $REGION 2>/dev/null || echo "Repo exists"

# Get repository URI
REPO_URI=$(aws ecr-public describe-repositories --repository-names $IMAGE_NAME --region $REGION --query "repositories[0].repositoryUri" --output text)

# Tag the Docker image
docker tag $IMAGE_NAME:$IMAGE_TAG $REPO_URI:$IMAGE_TAG

# Push the Docker image
docker push $REPO_URI:$IMAGE_TAG

# Done! Your image is now public
echo "Image pushed to: $REPO_URI:$IMAGE_TAG"
