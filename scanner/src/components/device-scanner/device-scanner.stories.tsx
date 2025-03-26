import React from 'react';
import type {Meta, StoryObj} from '@storybook/react';

import {device-scanner} from './device-scanner';

const meta: Meta<typeof device-scanner> = {
  component: device-scanner,
};

export default meta;

type Story = StoryObj<typeof device-scanner>;

export const Basic: Story = {args: {}};
