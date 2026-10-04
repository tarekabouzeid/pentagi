import { expect, test } from '../../fixtures/test.ts';
import { expectCleanPage } from '../../helpers/errors.ts';
import { APPROVAL_REASON, APPROVAL_TOOL, approvalsCassette } from '../../mocks/cassettes/approvals.ts';

test.describe('tool approvals', { tag: '@flows' }, () => {
    test.use({ cassette: approvalsCassette() });

    test('lists a waiting tool call and records the operator approving it', async ({ page, pageErrorLog }) => {
        await page.goto('/flows/5');
        await expect(page.locator('header').getByRole('button', { name: 'Toggle favorite' })).toBeEnabled();

        await page.getByRole('tab', { name: 'Approvals' }).click();

        const card = page.getByTestId('tool-approval-card');
        await expect(card).toHaveCount(1);
        await expect(card.getByText(APPROVAL_TOOL, { exact: true })).toBeVisible();
        await expect(card.getByText(APPROVAL_REASON)).toBeVisible();
        await expect(card.getByText('pending')).toBeVisible();

        await card.getByRole('button', { name: 'Approve' }).click();

        // Only the update frame carries the card past "pending" on a later fetch, and it
        // fires only after the mutation matched approvalId 7 with decision "approved".
        await expect(card.getByText('approved')).toBeVisible();
        await expect(card.getByRole('button', { name: 'Approve' })).toHaveCount(0);

        expectCleanPage(pageErrorLog);
    });
});
