export function requestResultIsCurrent(
  activeProfile,
  requestProfile,
  currentGeneration,
  requestGeneration
) {
  return activeProfile === requestProfile && currentGeneration === requestGeneration
}

export function saveResultIsCurrent(
  activeProfile,
  saveProfile,
  currentGeneration,
  saveGeneration
) {
  return activeProfile === saveProfile && currentGeneration === saveGeneration
}

export function saveResultCanReplaceDraft(
  activeProfile,
  saveProfile,
  currentSaveGeneration,
  saveGeneration,
  currentDraftGeneration,
  submittedDraftGeneration
) {
  return saveResultIsCurrent(activeProfile, saveProfile, currentSaveGeneration, saveGeneration)
    && currentDraftGeneration === submittedDraftGeneration
}

export function clearSavedCredentialDraft(currentValues, submittedValues, savedKinds = Object.keys(submittedValues)) {
  const saved = new Set(savedKinds)
  return Object.fromEntries(
    Object.entries(currentValues).map(([kind, value]) => [
      kind,
      saved.has(kind) && value === submittedValues[kind] ? '' : value
    ])
  )
}

export function profileScopedGrantDraft(draft, profile) {
  if (draft?.profile !== profile) return { profile, board: '', task: '' }
  return {
    profile,
    board: typeof draft.board === 'string' ? draft.board : '',
    task: typeof draft.task === 'string' ? draft.task : ''
  }
}
