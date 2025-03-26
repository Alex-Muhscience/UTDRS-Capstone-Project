import React from 'react';
import type {Meta, StoryObj} from '@storybook/react';

import {Makefile} from './Makefile';

const meta: Meta<typeof Makefile> = {
  component: Makefile,
};

export default meta;

type Story = StoryObj<typeof Makefile>;

export const Basic: Story = {args: {}};
