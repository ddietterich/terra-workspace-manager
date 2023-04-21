package bio.terra.workspace.service.notsam;

import bio.terra.cloudres.google.bigquery.BigQueryCow;
import bio.terra.common.exception.BadRequestException;
import bio.terra.stairway.FlightDebugInfo;
import bio.terra.stairway.StepStatus;
import bio.terra.workspace.app.configuration.external.FeatureConfiguration;
import bio.terra.workspace.common.BaseConnectedTest;
import bio.terra.workspace.common.GcpCloudUtils;
import bio.terra.workspace.common.StairwayTestUtils;
import bio.terra.workspace.common.fixtures.ControlledResourceFixtures;
import bio.terra.workspace.common.logging.model.ActivityLogChangeDetails;
import bio.terra.workspace.common.logging.model.ActivityLogChangedTarget;
import bio.terra.workspace.common.utils.MockMvcUtils;
import bio.terra.workspace.common.utils.RetryUtils;
import bio.terra.workspace.common.utils.TestUtils;
import bio.terra.workspace.connected.UserAccessUtils;
import bio.terra.workspace.connected.WorkspaceConnectedTestUtils;
import bio.terra.workspace.db.ResourceDao;
import bio.terra.workspace.generated.model.ApiGcpBigQueryDatasetCreationParameters;
import bio.terra.workspace.generated.model.ApiGcpBigQueryDatasetUpdateParameters;
import bio.terra.workspace.generated.model.ApiGcpGcsBucketDefaultStorageClass;
import bio.terra.workspace.generated.model.ApiGcpGcsBucketResource;
import bio.terra.workspace.generated.model.ApiIamRole;
import bio.terra.workspace.generated.model.ApiWorkspaceDescription;
import bio.terra.workspace.service.crl.CrlService;
import bio.terra.workspace.service.iam.AuthenticatedUserRequest;
import bio.terra.workspace.service.iam.model.WsmIamRole;
import bio.terra.workspace.service.job.JobService;
import bio.terra.workspace.service.job.exception.InvalidResultStateException;
import bio.terra.workspace.service.logging.WorkspaceActivityLogService;
import bio.terra.workspace.service.resource.WsmResourceService;
import bio.terra.workspace.service.resource.controlled.ControlledResourceService;
import bio.terra.workspace.service.resource.controlled.cloud.gcp.bqdataset.ControlledBigQueryDatasetResource;
import bio.terra.workspace.service.resource.controlled.cloud.gcp.bqdataset.CreateBigQueryDatasetStep;
import bio.terra.workspace.service.resource.controlled.cloud.gcp.bqdataset.DeleteBigQueryDatasetStep;
import bio.terra.workspace.service.resource.controlled.cloud.gcp.bqdataset.UpdateBigQueryDatasetStep;
import bio.terra.workspace.service.resource.controlled.flight.delete.DeleteMetadataStep;
import bio.terra.workspace.service.resource.exception.ResourceNotFoundException;
import bio.terra.workspace.service.resource.model.CommonUpdateParameters;
import bio.terra.workspace.service.resource.model.WsmResourceType;
import bio.terra.workspace.service.workspace.GcpCloudContextService;
import bio.terra.workspace.service.workspace.WorkspaceService;
import bio.terra.workspace.service.workspace.model.OperationType;
import bio.terra.workspace.service.workspace.model.Workspace;
import com.google.api.client.googleapis.json.GoogleJsonResponseException;
import com.google.api.services.bigquery.model.Dataset;
import com.google.cloud.storage.BlobId;
import com.google.cloud.storage.BlobInfo;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageException;
import com.google.cloud.storage.StorageOptions;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.jupiter.api.condition.DisabledIfEnvironmentVariable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import javax.annotation.Nullable;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static bio.terra.workspace.common.fixtures.ControlledResourceFixtures.DEFAULT_CREATED_BIG_QUERY_PARTITION_LIFETIME;
import static bio.terra.workspace.common.fixtures.ControlledResourceFixtures.DEFAULT_CREATED_BIG_QUERY_TABLE_LIFETIME;
import static bio.terra.workspace.common.utils.MockMvcUtils.WORKSPACES_V1_BY_UUID_PATH_FORMAT;
import static bio.terra.workspace.common.utils.MockMvcUtils.addAuth;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Tag("connected")
public class NotSamTest extends BaseConnectedTest {
  private static final Logger logger = LoggerFactory.getLogger(NotSamTest.class);
  private static final String DEFAULT_LOCATION = "us-central1";

  // Store workspaceId instead of workspace so that for local development, one can easily use a
  // previously created workspace.
  private UUID workspaceId;
  private UserAccessUtils.TestUser user;
  private String projectId;

  @Autowired private ControlledResourceService controlledResourceService;
  @Autowired private CrlService crlService;
  @Autowired private FeatureConfiguration features;
  @Autowired private GcpCloudContextService gcpCloudContextService;
  @Autowired private JobService jobService;
  @Autowired private UserAccessUtils userAccessUtils;
  @Autowired private WorkspaceConnectedTestUtils workspaceUtils;
  @Autowired private WorkspaceService workspaceService;
  @Autowired private ResourceDao resourceDao;
  @Autowired private WorkspaceActivityLogService workspaceActivityLogService;
  @Autowired private WsmResourceService wsmResourceService;
  @Autowired private MockMvc mockMvc;
  @Autowired private MockMvcUtils mockMvcUtils;
  @Autowired private GcpCloudUtils cloudUtils;

  @Test
  public void demoTest() throws Exception {
    // Create a workspace and cloud context
    logger.info("CREATE WORKSPACE AND VALIDATE ACCESS");
    user = userAccessUtils.defaultUser();
    workspaceId =
        workspaceUtils
            .createWorkspaceWithGcpContext(userAccessUtils.defaultUserAuthRequest())
            .getWorkspaceId();
    projectId = gcpCloudContextService.getRequiredGcpProject(workspaceId);

    // Check that we have the expected role
    WsmIamRole highestRole =
      workspaceService.getHighestRole(workspaceId, userAccessUtils.defaultUserAuthRequest());
    assertEquals(highestRole, WsmIamRole.OWNER);

    logger.info("GRANT DISCOVERER");
    mockMvcUtils.grantRole(
      userAccessUtils.defaultUserAuthRequest(),
      workspaceId,
      WsmIamRole.DISCOVERER,
      userAccessUtils.getSecondUserEmail());

    logger.info("DISCOVERER CANNOT GET THE WORKSPACE");
    getWorkspaceExpectingError(
      userAccessUtils.secondUserAuthRequest(),
      workspaceId,
      HttpStatus.SC_FORBIDDEN);

    logger.info("REVOKE DISCOVERER");
    mockMvcUtils.removeRole(
      userAccessUtils.defaultUserAuthRequest(),
      workspaceId,
      WsmIamRole.DISCOVERER,
      userAccessUtils.getSecondUserEmail());

    logger.info("GRANT READER");
    mockMvcUtils.grantRole(
      userAccessUtils.defaultUserAuthRequest(),
      workspaceId,
      WsmIamRole.READER,
      userAccessUtils.getSecondUserEmail());

    logger.info("READER CAN GET THE WORKSPACE");
    ApiWorkspaceDescription workspace = mockMvcUtils.getWorkspace(
      userAccessUtils.secondUserAuthRequest(),
      workspaceId);
    assertEquals(workspace.getHighestRole(), ApiIamRole.READER);

    logger.info("OWNER CREATES A BUCKET AND STORES A FILE IN IT");
    // Create a shared bucket in the workspace
    String sourceResourceName = TestUtils.appendRandomNumber("demo-bucket-resource");
    String sourceBucketName = TestUtils.appendRandomNumber("demo-bucket-name");
    ApiGcpGcsBucketResource sourceBucket =
      mockMvcUtils
        .createControlledGcsBucket(
          userAccessUtils.defaultUserAuthRequest(),
          workspaceId,
          sourceResourceName,
          sourceBucketName,
          DEFAULT_LOCATION,
          null,
          null)
        .getGcpBucket();
    assertEquals(sourceBucket.getMetadata().getName(), sourceResourceName);

    cloudUtils.addFileToBucket(
      userAccessUtils.defaultUser().getGoogleCredentials(), projectId, sourceBucketName);

    logger.info("READER TRIES AND FAILS TO STORE A FILE IN THE BUCKET");
    try {
      Storage storageClient = StorageOptions.newBuilder()
        .setCredentials(userAccessUtils.secondUser().getGoogleCredentials())
        .setProjectId(projectId)
        .build()
        .getService();
      BlobId blobId = BlobId.of(sourceBucketName, TestUtils.appendRandomNumber("foo"));
      BlobInfo blobInfo = BlobInfo.newBuilder(blobId).build();

      // Create a blob with retry to allow permission propagation
      storageClient.create(blobInfo, "foobar".getBytes(StandardCharsets.UTF_8));
    } catch (StorageException e) {
      logger.info("Expected failure", e);
    }

    logger.info("GRANT WRITER TO THAT USER");
    mockMvcUtils.grantRole(
      userAccessUtils.defaultUserAuthRequest(),
      workspaceId,
      WsmIamRole.WRITER,
      userAccessUtils.getSecondUserEmail());

    // Now we should be able to write a file to the bucket
    // And there should not be propagation delay.
    logger.info("WRITER IS ABLE TO STORE A FILE IN THE BUCKET");
    try {
      Storage storageClient = StorageOptions.newBuilder()
        .setCredentials(userAccessUtils.secondUser().getGoogleCredentials())
        .setProjectId(projectId)
        .build()
        .getService();
      BlobId blobId = BlobId.of(sourceBucketName, TestUtils.appendRandomNumber("foo"));
      BlobInfo blobInfo = BlobInfo.newBuilder(blobId).build();

      // Create a blob with retry to allow permission propagation
      storageClient.create(blobInfo, "foobar".getBytes(StandardCharsets.UTF_8));
    } catch (StorageException e) {
      logger.info("Oh no!! Unexpected failure", e);
    }
  }

  private void getWorkspaceExpectingError(
    AuthenticatedUserRequest userRequest,
    UUID id,
    int statusCode)
    throws Exception {
    MockHttpServletRequestBuilder requestBuilder =
      get(String.format(WORKSPACES_V1_BY_UUID_PATH_FORMAT, id));
    mockMvc.perform(addAuth(requestBuilder, userRequest)).andExpect(status().is(statusCode));
  }

}
