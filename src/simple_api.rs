use crate::{
    NFSCRSError, NFSClientSession, OpenOptions, OpenedFile, fattr4_utils::FAttr4Builder,
    nfscrs_types::AbsolutePath,
};

impl NFSClientSession {
    pub fn open_file_and_comfirm(
        &mut self,
        path: &AbsolutePath,
        open_options: OpenOptions,
    ) -> Result<OpenedFile, NFSCRSError> {
        let truncate = open_options.truncate;
        let lock_clone = self.open_owner_lock.clone();
        let _guard = lock_clone
            .lock()
            .map_err(|e| NFSCRSError::InnerError(e.into()))?;

        let mut opened_file = self.open(path, open_options)?;

        // Only when the OPEN4_RESULT_CONFIRM bit is set in rflags
        // will need open confirm operation
        if opened_file.need_confirm() {
            opened_file = self.open_confirm(opened_file)?;
        }

        if truncate {
            let mut fattr_builder = FAttr4Builder::new();
            fattr_builder.set_file_size(0);
            self.set_attr(
                &opened_file.file_handle,
                &fattr_builder.build(),
                &opened_file.state_id,
            )?;
        }
        Ok(opened_file)
    }
}
