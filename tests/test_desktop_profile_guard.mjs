import assert from 'node:assert/strict'
import test from 'node:test'

import {
  clearSavedCredentialDraft,
  profileScopedGrantDraft,
  requestResultIsCurrent,
  saveResultCanReplaceDraft,
  saveResultIsCurrent
} from '../desktop/profile_guard.mjs'

test('status response from a previous profile is rejected after a profile switch', () => {
  const requestProfile = 'profile-a'
  const requestGeneration = 1
  const activeProfile = 'profile-b'
  const currentGeneration = 2

  assert.equal(
    requestResultIsCurrent(activeProfile, requestProfile, currentGeneration, requestGeneration),
    false
  )
})

test('isolated instructions response is rejected after generation changes', () => {
  const requestProfile = 'profile-a'
  const requestGeneration = 4

  assert.equal(requestResultIsCurrent('profile-a', requestProfile, 5, requestGeneration), false)
  assert.equal(requestResultIsCurrent('profile-a', requestProfile, 4, requestGeneration), true)
})

test('async registry mutation stays stale after switching away and back to the same profile', () => {
  const requestProfile = 'profile-a'
  const requestGeneration = 7
  assert.equal(
    requestResultIsCurrent('profile-a', requestProfile, 9, requestGeneration),
    false
  )
})

test('save completion from a previous profile cannot refresh or mutate the active profile', () => {
  const saveProfile = 'profile-a'
  const saveGeneration = 1

  assert.equal(saveResultIsCurrent('profile-b', saveProfile, 2, saveGeneration), false)
  assert.equal(saveResultIsCurrent('profile-a', saveProfile, 1, saveGeneration), true)
})

test('older save stays stale after switching away and back to the same profile', () => {
  const profile = 'profile-a'
  const firstSaveGeneration = 1
  const generationAfterRoundTrip = 3
  const secondSaveGeneration = 4

  assert.equal(
    saveResultIsCurrent(profile, profile, generationAfterRoundTrip, firstSaveGeneration),
    false
  )
  assert.equal(saveResultIsCurrent(profile, profile, secondSaveGeneration, firstSaveGeneration), false)
  assert.equal(saveResultIsCurrent(profile, profile, secondSaveGeneration, secondSaveGeneration), true)
})

test('save response cannot replace draft edited after submission', () => {
  assert.equal(
    saveResultCanReplaceDraft('profile-a', 'profile-a', 5, 5, 9, 8),
    false
  )
  assert.equal(
    saveResultCanReplaceDraft('profile-a', 'profile-a', 5, 5, 8, 8),
    true
  )
})

test('credential save clears only values that still match the submitted snapshot', () => {
  assert.deepEqual(
    clearSavedCredentialDraft(
      { webhook: 'new-webhook', hmac: 'saved-hmac', pat: 'new-pat' },
      { webhook: 'saved-webhook', hmac: 'saved-hmac', pat: '' }
    ),
    { webhook: 'new-webhook', hmac: '', pat: 'new-pat' }
  )
})

test('partial credential save clears only successful drafts', () => {
  assert.deepEqual(
    clearSavedCredentialDraft(
      { webhook: 'saved-webhook', hmac: 'failed-hmac', pat: 'unsaved-pat' },
      { webhook: 'saved-webhook', hmac: 'failed-hmac', pat: 'unsaved-pat' },
      ['webhook']
    ),
    { webhook: '', hmac: 'failed-hmac', pat: 'unsaved-pat' }
  )
})

test('operator grant draft from a previous profile is discarded', () => {
  const draft = { profile: 'profile-a', board: 'restricted-board', task: 'task-7' }
  assert.deepEqual(profileScopedGrantDraft(draft, 'profile-b'), {
    profile: 'profile-b',
    board: '',
    task: ''
  })
  assert.deepEqual(draft, { profile: 'profile-a', board: 'restricted-board', task: 'task-7' })
})

test('operator grant draft remains available in its owning profile', () => {
  assert.deepEqual(
    profileScopedGrantDraft(
      { profile: 'profile-a', board: 'board', task: 'task-1' },
      'profile-a'
    ),
    { profile: 'profile-a', board: 'board', task: 'task-1' }
  )
})
