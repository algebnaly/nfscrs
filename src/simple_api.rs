use crate::{NFSCRSError, NFSClientSession, OpenOptions, OpenedFile, fattr4_utils::FAttr4Builder, nfscrs_types::AbsolutePath};
impl NFSClientSession {
    pub fn open_file_and_comfirm(
        &mut self,
        path: &AbsolutePath,
        open_options: OpenOptions,
    ) -> Result<OpenedFile, NFSCRSError> {
        let truncate = open_options.truncate;
        let opening_file = self.open(path, open_options)?;
        let opened_file = self.open_confirm(opening_file)?;
        if truncate {
            let mut  fattr_builder = FAttr4Builder::new();
            fattr_builder.set_file_size(0);
            self.set_attr(&opened_file.file_handle, &fattr_builder.build(), &opened_file.state_id)?;
        }
        Ok(opened_file)
    }
}
