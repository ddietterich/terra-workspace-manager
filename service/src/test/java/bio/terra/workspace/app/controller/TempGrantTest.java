package bio.terra.workspace.app.controller;

import bio.terra.workspace.app.configuration.external.FeatureConfiguration;
import bio.terra.workspace.common.BaseConnectedTest;
import bio.terra.workspace.common.GcpCloudUtils;
import bio.terra.workspace.common.utils.MockMvcUtils;
import bio.terra.workspace.common.utils.TestUtils;
import bio.terra.workspace.connected.UserAccessUtils;
import bio.terra.workspace.generated.model.ApiGcpAiNotebookInstanceResource;
import bio.terra.workspace.generated.model.ApiGcpBigQueryDatasetResource;
import bio.terra.workspace.generated.model.ApiGcpGcsBucketResource;
import bio.terra.workspace.generated.model.ApiWorkspaceDescription;
import bio.terra.workspace.service.crl.CrlService;
import bio.terra.workspace.service.iam.SamService;
import bio.terra.workspace.service.job.JobService;
import bio.terra.workspace.service.logging.WorkspaceActivityLogService;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.junit.After;
import org.junit.Before;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.MockMvc;

@Disabled("Only for manually testing temporary grants. Do not automate.")
@Tag("connected")
public class TempGrantTest extends BaseConnectedTest {
  private static final Logger logger = LoggerFactory.getLogger(TempGrantTest.class);

  @Autowired MockMvc mockMvc;
  @Autowired MockMvcUtils mockMvcUtils;
  @Autowired ObjectMapper objectMapper;
  @Autowired UserAccessUtils userAccessUtils;
  @Autowired JobService jobService;
  @Autowired GcpCloudUtils cloudUtils;
  @Autowired FeatureConfiguration features;
  @Autowired CrlService crlService;
  @Autowired WorkspaceActivityLogService activityLogService;
  @Autowired SamService samService;

  private UUID workspaceId;

  private boolean timeToFinish;

  @Before
  public void startup() throws Exception {
    timeToFinish = false;
  }

  @After
  public void cleanup() throws Exception {
    mockMvcUtils.deleteWorkspace(userAccessUtils.defaultUserAuthRequest(), workspaceId);
  }

  @Test
  public void setupAndWaitBucket() throws Exception {
    workspaceId =
        mockMvcUtils
            .createWorkspaceWithCloudContext(userAccessUtils.defaultUserAuthRequest())
            .getId();
    ApiWorkspaceDescription workspace =
        mockMvcUtils.getWorkspace(userAccessUtils.defaultUserAuthRequest(), workspaceId);
    String projectId = workspace.getGcpContext().getProjectId();

    logger.info("Created workspace {} with project {}", workspaceId, projectId);

    String sourceResourceName = TestUtils.appendRandomNumber("source-resource-name");
    String sourceBucketName = TestUtils.appendRandomNumber("source-bucket-name");
    ApiGcpGcsBucketResource sourceBucket =
        mockMvcUtils
            .createControlledGcsBucket(
                userAccessUtils.defaultUserAuthRequest(),
                workspaceId,
                sourceResourceName,
                sourceBucketName,
                null,
                null,
                null)
            .getGcpBucket();
    cloudUtils.addFileToBucket(
        userAccessUtils.defaultUser().getGoogleCredentials(), projectId, sourceBucketName);

    // So I can end the test and run cleanup when I'm done debugging
    while (!timeToFinish) {
      TimeUnit.MINUTES.sleep(1);
    }
  }

  @Test
  public void setupAndWaitNotebook() throws Exception {
    workspaceId =
        mockMvcUtils
            .createWorkspaceWithCloudContext(userAccessUtils.defaultUserAuthRequest())
            .getId();
    ApiWorkspaceDescription workspace =
        mockMvcUtils.getWorkspace(userAccessUtils.defaultUserAuthRequest(), workspaceId);
    String projectId = workspace.getGcpContext().getProjectId();

    logger.info("Created workspace {} with project {}", workspaceId, projectId);

    ApiGcpAiNotebookInstanceResource notebook =
        mockMvcUtils
            .createAiNotebookInstance(userAccessUtils.defaultUserAuthRequest(), workspaceId, null)
            .getAiNotebookInstance();

    // So I can end the test and run cleanup when I'm done debugging
    while (!timeToFinish) {
      TimeUnit.MINUTES.sleep(1);
    }
  }

  @Test
  public void setupAndWaitBigQuery() throws Exception {
    workspaceId =
        mockMvcUtils
            .createWorkspaceWithCloudContext(userAccessUtils.defaultUserAuthRequest())
            .getId();
    ApiWorkspaceDescription workspace =
        mockMvcUtils.getWorkspace(userAccessUtils.defaultUserAuthRequest(), workspaceId);
    String projectId = workspace.getGcpContext().getProjectId();

    logger.info("Created workspace {} with project {}", workspaceId, projectId);

    String sourceResourceName = TestUtils.appendRandomNumber("sourceresourcename");
    String sourceDatasetName = TestUtils.appendRandomNumber("sourcedatasetname");

    ApiGcpBigQueryDatasetResource resource =
        mockMvcUtils
            .createControlledBqDataset(
                userAccessUtils.defaultUserAuthRequest(),
                workspaceId,
                sourceResourceName,
                sourceDatasetName,
                null,
                null,
                null)
            .getBigQueryDataset();
    cloudUtils.populateBqTable(
        userAccessUtils.defaultUser().getGoogleCredentials(),
        resource.getAttributes().getProjectId(),
        sourceDatasetName);

    // So I can end the test and run cleanup when I'm done debugging
    while (!timeToFinish) {
      TimeUnit.MINUTES.sleep(1);
    }
  }
}
