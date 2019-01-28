/** @file
 *
 *  A brief file description
 *
 *  @section license License
 *
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include "Http3FrameDispatcher.h"

#include "tscore/Diags.h"
#include "QUICIntUtil.h"

#include "Http3DebugNames.h"

//
// Frame Dispatcher
//

void
Http3FrameDispatcher::add_handler(Http3FrameHandler *handler)
{
  for (Http3FrameType t : handler->interests()) {
    this->_handlers[static_cast<uint8_t>(t)].push_back(handler);
  }
}

Http3ErrorUPtr
Http3FrameDispatcher::on_read_ready(QUICStreamIO &stream_io, uint64_t &nread)
{
  std::shared_ptr<const Http3Frame> frame(nullptr);
  Http3ErrorUPtr error = Http3ErrorUPtr(new Http3NoError());
  nread                = 0;

  while (true) {
    if (this->_reading_state == READING_LENGTH_LEN) {
      // Read a length of Length field
      uint8_t head;
      if (stream_io.peek(&head, 1) <= 0) {
        break;
      }
      this->_reading_frame_length_len = QUICVariableInt::size(&head);
      this->_reading_state            = READING_PAYLOAD_LEN;
    }

    if (this->_reading_state == READING_PAYLOAD_LEN) {
      // Read a payload length
      uint8_t length_buf[8];
      if (stream_io.peek(length_buf, this->_reading_frame_length_len) != this->_reading_frame_length_len) {
        break;
      }
      size_t dummy;
      if (QUICVariableInt::decode(this->_reading_frame_payload_len, dummy, length_buf, sizeof(length_buf)) < 0) {
        error = Http3ErrorUPtr(new Http3StreamError());
      }
      this->_reading_state = READING_PAYLOAD;
    }

    // Create a frame
    // Length field length + Type field length (1) + Payload length
    size_t frame_len = this->_reading_frame_length_len + 1 + this->_reading_frame_payload_len;
    frame            = this->_frame_factory.fast_create(stream_io, frame_len);
    if (frame == nullptr) {
      break;
    }

    // Consume buffer if frame is created
    nread += frame_len;
    stream_io.consume(nread);

    // Dispatch
    Http3FrameType type = frame->type();
    Debug("http3", "[RX] [%d] | %s", stream_io.stream_id(), Http3DebugNames::frame_type(type));
    std::vector<Http3FrameHandler *> handlers = this->_handlers[static_cast<uint8_t>(type)];
    for (auto h : handlers) {
      error = h->handle_frame(frame);
      if (error->cls != Http3ErrorClass::NONE) {
        return error;
      }
    }
    this->_reading_state = READING_LENGTH_LEN;
  }

  return error;
}
