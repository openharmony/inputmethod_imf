/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import commonEventManager from '@ohos.commonEventManager';
import display from '@ohos.display';
import inputMethodEngine from '@ohos.inputMethodEngine';
import InputMethodExtensionContext from '@ohos.InputMethodExtensionContext';

// Call the getInputMethodAbility method of the input method framework to get the instance
const inputMethodAbility: inputMethodEngine.InputMethodAbility = inputMethodEngine.getInputMethodAbility();
const DEFAULT_DIRECTION: number = 1;
const DEFAULT_LENGTH: number = 1;
const DEFAULT_SELECT_RANGE: number = 10;

enum TEST_RESULT_CODE {
  SUCCESS,
  FAILED
}

enum TEST_FUNCTION {
  INSERT_TEXT_SYNC,
  MOVE_CURSOR_SYNC,
  GET_ATTRIBUTE_SYNC,
  SELECT_BY_RANGE_SYNC,
  SELECT_BY_MOVEMENT_SYNC,
  GET_INDEX_AT_CURSOR_SYNC,
  DELETE_FORWARD_SYNC,
  DELETE_BACKWARD_SYNC,
  GET_FORWARD_SYNC,
  GET_BACKWARD_SYNC,
  CHANGE_FLAG_TO_FIXED,
  CHANGE_FLAG_TO_FLOATING,
}

export class KeyboardController {
  private TAG: string = 'inputDemo: KeyboardController ';
  private mContext: InputMethodExtensionContext | undefined = undefined; // save the context property of InputMethodExtensionAbility
  private panel: inputMethodEngine.Panel | undefined = undefined;
  private subscriber = undefined;

  constructor() {
  }

  public onCreate(context: InputMethodExtensionContext): void {
    this.mContext = context;
    this.initWindow(); // init window
    this.registerListener(); //register input listener
  }

  public onDestroy(): void {
    this.unRegisterListener();
    if (this.panel) {
      this.panel.hide();
      inputMethodAbility.destroyPanel(this.panel);
    }
    this.mContext.destroy();
  }

  private initWindow(): void {
    if (this.mContext === undefined) {
      return;
    }
    let dis = display.getDefaultDisplaySync();
    let dWidth = dis.width;
    let dHeight = dis.height;
    let keyHeightRate = 0.47;
    let keyHeight = dHeight * keyHeightRate;
    let nonBarPosition = dHeight - keyHeight;
    let panelInfo: inputMethodEngine.PanelInfo = {
      type: inputMethodEngine.PanelType.SOFT_KEYBOARD,
      flag: inputMethodEngine.PanelFlag.FLG_FIXED
    };
    inputMethodAbility.createPanel(this.mContext, panelInfo).then(async (inputPanel: inputMethodEngine.Panel) => {
      this.panel = inputPanel;
      if (this.panel) {
        await this.panel.resize(dWidth, keyHeight);
        await this.panel.moveTo(0, nonBarPosition);
        await this.panel.setUiContent('pages/Index');
      }
    });
  }

  publishCommonEvent(event: string, codeNumber: number): void {
    this.addLog(`[inputDemo] publish event, event= ${event}, codeNumber= ${codeNumber}`);
    commonEventManager.publish(event, { code: codeNumber }, (err) => {
      if (err) {
        this.addLog(`inputDemo publish ${event} failed, err = ${JSON.stringify(err)}`);
      } else {
        this.addLog(`inputDemo publish ${event} success`);
      }
    })
  }

  private registerListener(): void {
    this.registerInputListener();
    let subscribeInfo = {
      events: ['syncTestFunction']
    }
    commonEventManager.createSubscriber(subscribeInfo).then((data) => {
      this.subscriber = data;
      commonEventManager.subscribe(this.subscriber, (err, eventData) => {
        this.addLog(`[inputDemo] subscribe, eventData.code = ${eventData.code}`);
        if (globalThis.textInputClient === undefined) {
          return;
        }
        switch (eventData.code) {
          case TEST_FUNCTION.INSERT_TEXT_SYNC:
            globalThis.textInputClient.insertTextSync("text");
            break;
          case TEST_FUNCTION.MOVE_CURSOR_SYNC:
            globalThis.textInputClient.moveCursorSync(DEFAULT_DIRECTION);
            break;
          case TEST_FUNCTION.GET_ATTRIBUTE_SYNC:
            this.getAttributeSync();
            break;
          case TEST_FUNCTION.SELECT_BY_RANGE_SYNC:
            globalThis.textInputClient.selectByRangeSync({ start: 0, end: DEFAULT_SELECT_RANGE });
            break;
          case TEST_FUNCTION.SELECT_BY_MOVEMENT_SYNC:
            globalThis.textInputClient.selectByMovementSync({ direction: inputMethodEngine.CURSOR_LEFT });
            break;
          case TEST_FUNCTION.GET_INDEX_AT_CURSOR_SYNC:
            this.getIndexAtCursorSync()
            break;
          case TEST_FUNCTION.DELETE_FORWARD_SYNC:
            globalThis.textInputClient.deleteForwardSync(DEFAULT_LENGTH);
            break;
          case TEST_FUNCTION.DELETE_BACKWARD_SYNC:
            globalThis.textInputClient.deleteBackwardSync(DEFAULT_LENGTH);
            break;
          case TEST_FUNCTION.GET_FORWARD_SYNC:
            this.getForwardSync();
            break;
          case TEST_FUNCTION.GET_BACKWARD_SYNC:
            this.getBackwardSync();
            break;
          case TEST_FUNCTION.CHANGE_FLAG_TO_FIXED:
            this.changePanelFlag(inputMethodEngine.PanelFlag.FLG_FIXED);
            break;
          case TEST_FUNCTION.CHANGE_FLAG_TO_FLOATING:
            this.changePanelFlag(inputMethodEngine.PanelFlag.FLG_FLOATING);
            break;
          default:
            break;
        }
      })
    })
  }

  private registerInputListener(): void { // 注册对输入法框架服务的开启及停止事件监听
    inputMethodAbility.on('inputStart', (kbController, textInputClient) => {
      globalThis.textInputClient = textInputClient; // 此为输入法客户端实例，由此调用输入法框架提供给输入法应用的功能接口
      globalThis.keyboardController = kbController;
    })
    inputMethodAbility.on('inputStop', () => {
      this.onDestroy();
    });
  }

  private unRegisterListener(): void {
    inputMethodAbility.off('inputStart');
    inputMethodAbility.off('inputStop', () => {
    });
  }

  getBackwardSync() {
    let backward: string = globalThis.textInputClient.getBackwardSync(1);
    if (backward.length >= 0) {
      this.publishCommonEvent('getBackwardSyncResult', TEST_RESULT_CODE.SUCCESS);
    } else {
      this.publishCommonEvent('getBackwardSyncResult', TEST_RESULT_CODE.FAILED);
    }
  }

  getForwardSync() {
    let forward: string = globalThis.textInputClient.getForwardSync(1);
    if (forward.length >= 0) {
      this.publishCommonEvent('getForwardSyncResult', TEST_RESULT_CODE.SUCCESS);
    } else {
      this.publishCommonEvent('getForwardSyncResult', TEST_RESULT_CODE.FAILED);
    }
  }

  async getAttributeSync() {
    try {
      let editAttribute = globalThis.textInputClient.getEditorAttributeSync();
      let editAttribute1 = await globalThis.textInputClient.getEditorAttribute();
      this.addLog(`[inputDemo] publish getEditorAttributeSync editAttribute= ${JSON.stringify(editAttribute)}`);
      if(editAttribute.inputPattern == editAttribute1.inputPattern && editAttribute.enterKeyType == editAttribute1.enterKeyType) {
        this.publishCommonEvent('getEditorAttributeSyncResult', TEST_RESULT_CODE.SUCCESS);
      } else{
        this.publishCommonEvent('getEditorAttributeSyncResult', TEST_RESULT_CODE.FAILED);
      }
    } catch (err) {
      this.publishCommonEvent('getEditorAttributeSyncResult', TEST_RESULT_CODE.FAILED);
    }
  }

  getIndexAtCursorSync() {
    try {
      let index = globalThis.textInputClient.getTextIndexAtCursorSync();
      this.addLog(`[inputDemo] publish getTextIndexAtCursorSync index= ${index}`);
      this.publishCommonEvent('getTextIndexAtCursorSyncResult', TEST_RESULT_CODE.SUCCESS);
    } catch (err) {
      this.publishCommonEvent('getTextIndexAtCursorSyncResult', TEST_RESULT_CODE.FAILED);
    }
  }

  changePanelFlag(panelFlag: inputMethodEngine.PanelFlag) {
    try {
      this.panel.hide((err) => {
        if (err) {
          this.addLog(`Failed to hide panel: ${JSON.stringify(err)}`);
          this.publishCommonEvent('changeFlag', TEST_RESULT_CODE.FAILED);
          return;
        }
        this.panel.changeFlag(panelFlag);
        this.panel.show((err) => {
          this.addLog(`Failed to show panel: ${JSON.stringify(err)}`);
          this.publishCommonEvent('changeFlag', TEST_RESULT_CODE.SUCCESS);
        });
      });
    } catch (err) {
      this.addLog(`failed: ${JSON.stringify(err)}`);
      this.publishCommonEvent('changeFlag', TEST_RESULT_CODE.FAILED);
    }
  }

  private addLog(message): void {
    console.log(this.TAG + message)
  }
}

const keyboardController = new KeyboardController();

export default keyboardController;