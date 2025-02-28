package bio.terra.workspace.app.controller;

import static bio.terra.workspace.common.utils.MockMvcUtils.USER_REQUEST;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import bio.terra.workspace.common.BaseUnitTest;
import bio.terra.workspace.common.utils.MockMvcUtils;
import bio.terra.workspace.generated.model.ApiCloningInstructionsEnum;
import bio.terra.workspace.service.iam.model.WsmIamRole;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.UUID;
import org.apache.http.HttpStatus;
import org.broadinstitute.dsde.workbench.client.sam.model.UserStatusInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

@AutoConfigureMockMvc
public class ReferencedGcpResourceControllerTest extends BaseUnitTest {

  @Autowired MockMvc mockMvc;
  @Autowired MockMvcUtils mockMvcUtils;
  @Autowired ObjectMapper objectMapper;

  @BeforeEach
  public void setUp() throws InterruptedException {
    // Needed for workspace creation as logging is triggered when a workspace is created in
    // `WorkspaceActivityLogHook` where we extract the user request information and log it to
    // activity log.
    when(mockSamService().getUserStatusInfo(any()))
        .thenReturn(
            new UserStatusInfo()
                .userEmail(USER_REQUEST.getEmail())
                .userSubjectId(USER_REQUEST.getSubjectId()));
    when(mockSamService().getUserEmailFromSamAndRethrowOnInterrupt(any()))
        .thenReturn(USER_REQUEST.getEmail());
    // Needed for assertion that requester has role on workspace.
    when(mockSamService().listRequesterRoles(any(), any(), any()))
        .thenReturn(List.of(WsmIamRole.OWNER));
  }

  @Test
  public void cloneReferencedDataRepoSnapshot_copyDefinition_throws400() throws Exception {
    UUID workspaceId = mockMvcUtils.createWorkspaceWithoutCloudContext(USER_REQUEST).getId();

    mockMvcUtils.cloneReferencedDataRepoSnapshot(
        USER_REQUEST,
        workspaceId,
        /*sourceResourceId=*/ UUID.randomUUID(),
        /*destWorkspaceId=*/ workspaceId,
        ApiCloningInstructionsEnum.DEFINITION,
        /*destResourceName=*/ null,
        HttpStatus.SC_BAD_REQUEST);
  }

  @Test
  public void cloneReferencedDataRepoSnapshot_copyResource_throws400() throws Exception {
    UUID workspaceId = mockMvcUtils.createWorkspaceWithoutCloudContext(USER_REQUEST).getId();

    mockMvcUtils.cloneReferencedDataRepoSnapshot(
        USER_REQUEST,
        workspaceId,
        /*sourceResourceId=*/ UUID.randomUUID(),
        /*destWorkspaceId=*/ workspaceId,
        ApiCloningInstructionsEnum.RESOURCE,
        /*destResourceName=*/ null,
        HttpStatus.SC_BAD_REQUEST);
  }

  @Test
  public void cloneReferencedBqDataset_copyDefinition_throws400() throws Exception {
    UUID workspaceId = mockMvcUtils.createWorkspaceWithoutCloudContext(USER_REQUEST).getId();

    mockMvcUtils.cloneReferencedBqDataset(
        USER_REQUEST,
        workspaceId,
        /*sourceResourceId=*/ UUID.randomUUID(),
        /*destWorkspaceId=*/ workspaceId,
        ApiCloningInstructionsEnum.DEFINITION,
        /*destResourceName=*/ null,
        HttpStatus.SC_BAD_REQUEST);
  }

  @Test
  public void cloneReferencedBqDataset_copyResource_throws400() throws Exception {
    UUID workspaceId = mockMvcUtils.createWorkspaceWithoutCloudContext(USER_REQUEST).getId();

    mockMvcUtils.cloneReferencedBqDataset(
        USER_REQUEST,
        workspaceId,
        /*sourceResourceId=*/ UUID.randomUUID(),
        /*destWorkspaceId=*/ workspaceId,
        ApiCloningInstructionsEnum.RESOURCE,
        /*destResourceName=*/ null,
        HttpStatus.SC_BAD_REQUEST);
  }

  @Test
  public void cloneReferencedBqTable_copyDefinition_throws400() throws Exception {
    UUID workspaceId = mockMvcUtils.createWorkspaceWithoutCloudContext(USER_REQUEST).getId();

    mockMvcUtils.cloneReferencedBqTable(
        USER_REQUEST,
        workspaceId,
        /*sourceResourceId=*/ UUID.randomUUID(),
        /*destWorkspaceId=*/ workspaceId,
        ApiCloningInstructionsEnum.DEFINITION,
        /*destResourceName=*/ null,
        HttpStatus.SC_BAD_REQUEST);
  }

  @Test
  public void cloneReferencedBqTable_copyResource_throws400() throws Exception {
    UUID workspaceId = mockMvcUtils.createWorkspaceWithoutCloudContext(USER_REQUEST).getId();

    mockMvcUtils.cloneReferencedBqTable(
        USER_REQUEST,
        workspaceId,
        /*sourceResourceId=*/ UUID.randomUUID(),
        /*destWorkspaceId=*/ workspaceId,
        ApiCloningInstructionsEnum.RESOURCE,
        /*destResourceName=*/ null,
        HttpStatus.SC_BAD_REQUEST);
  }

  @Test
  public void cloneReferencedGcsBucket_copyDefinition_throws400() throws Exception {
    UUID workspaceId = mockMvcUtils.createWorkspaceWithoutCloudContext(USER_REQUEST).getId();

    mockMvcUtils.cloneReferencedGcsBucket(
        USER_REQUEST,
        workspaceId,
        /*sourceResourceId=*/ UUID.randomUUID(),
        /*destWorkspaceId=*/ workspaceId,
        ApiCloningInstructionsEnum.DEFINITION,
        /*destResourceName=*/ null,
        HttpStatus.SC_BAD_REQUEST);
  }

  @Test
  public void cloneReferencedGcsBucket_copyResource_throws400() throws Exception {
    UUID workspaceId = mockMvcUtils.createWorkspaceWithoutCloudContext(USER_REQUEST).getId();

    mockMvcUtils.cloneReferencedGcsBucket(
        USER_REQUEST,
        workspaceId,
        /*sourceResourceId=*/ UUID.randomUUID(),
        /*destWorkspaceId=*/ workspaceId,
        ApiCloningInstructionsEnum.RESOURCE,
        /*destResourceName=*/ null,
        HttpStatus.SC_BAD_REQUEST);
  }

  @Test
  public void cloneReferencedGcsObject_copyDefinition_throws400() throws Exception {
    UUID workspaceId = mockMvcUtils.createWorkspaceWithoutCloudContext(USER_REQUEST).getId();

    mockMvcUtils.cloneReferencedGcsObject(
        USER_REQUEST,
        workspaceId,
        /*sourceResourceId=*/ UUID.randomUUID(),
        /*destWorkspaceId=*/ workspaceId,
        ApiCloningInstructionsEnum.DEFINITION,
        /*destResourceName=*/ null,
        HttpStatus.SC_BAD_REQUEST);
  }

  @Test
  public void cloneReferencedGcsObject_copyResource_throws400() throws Exception {
    UUID workspaceId = mockMvcUtils.createWorkspaceWithoutCloudContext(USER_REQUEST).getId();

    mockMvcUtils.cloneReferencedGcsObject(
        USER_REQUEST,
        workspaceId,
        /*sourceResourceId=*/ UUID.randomUUID(),
        /*destWorkspaceId=*/ workspaceId,
        ApiCloningInstructionsEnum.RESOURCE,
        /*destResourceName=*/ null,
        HttpStatus.SC_BAD_REQUEST);
  }

  @Test
  public void cloneReferencedGitRepo_copyDefinition_throws400() throws Exception {
    UUID workspaceId = mockMvcUtils.createWorkspaceWithoutCloudContext(USER_REQUEST).getId();

    mockMvcUtils.cloneReferencedGitRepo(
        USER_REQUEST,
        workspaceId,
        /*sourceResourceId=*/ UUID.randomUUID(),
        /*destWorkspaceId=*/ workspaceId,
        ApiCloningInstructionsEnum.DEFINITION,
        /*destResourceName=*/ null,
        HttpStatus.SC_BAD_REQUEST);
  }

  @Test
  public void cloneReferencedGitRepo_copyResource_throws400() throws Exception {
    UUID workspaceId = mockMvcUtils.createWorkspaceWithoutCloudContext(USER_REQUEST).getId();

    mockMvcUtils.cloneReferencedGitRepo(
        USER_REQUEST,
        workspaceId,
        /*sourceResourceId=*/ UUID.randomUUID(),
        /*destWorkspaceId=*/ workspaceId,
        ApiCloningInstructionsEnum.RESOURCE,
        /*destResourceName=*/ null,
        HttpStatus.SC_BAD_REQUEST);
  }
}
