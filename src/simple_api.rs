use crate::{
    NFSCRSError, NFSClientSession, OpenOptions, OpenedFile, fattr4_utils::FAttr4Builder,
    nfscrs_error::NFSCRSInnerError, nfscrs_types::AbsolutePath,
};

impl NFSClientSession {
    pub fn open_file(
        &mut self,
        path: &AbsolutePath,
        open_options: OpenOptions,
    ) -> Result<OpenedFile, NFSCRSError> {
        let truncate = open_options.truncate;
        let open_owner_ref = self.open_owner.clone();

        let mut seq_id_and_path_guard = open_owner_ref.lock_seq_id_and_path(path)?;

        // let _guard = open_owner_ref
        //     .lock_path(path)// TODO: this is wrong, do not use per path lock here, we need lock
        //     .map_err(|e| NFSCRSInnerError::PoisonedMutex(format!("{:?}", e)))?;
        let seq_id_ref = &mut *seq_id_and_path_guard.seq_id_guard;
        let mut opened_file = self.open(path, open_options, seq_id_ref)?;

        if self.open_file_need_confirm(&opened_file)? {
            opened_file = self.open_confirm(opened_file, seq_id_ref)?;
        };

        let file_open_state = open_owner_ref.files.get(&opened_file.file_key).ok_or(
            NFSCRSInnerError::IllegalState("cannot found opened file".to_string()),
        )?;

        let state_id = file_open_state.get_state_id()?;

        if truncate {
            let mut fattr_builder = FAttr4Builder::new();
            fattr_builder.set_file_size(0);
            self.set_attr(&opened_file.file_handle, &fattr_builder.build(), &state_id)?;
        }
        Ok(opened_file)
    }
}
