.. Licensed to the Apache Software Foundation (ASF) under one or more
   contributor license agreements.  See the NOTICE file distributed
   with this work for additional information regarding copyright
   ownership.  The ASF licenses this file to you under the Apache
   License, Version 2.0 (the "License"); you may not use this file
   except in compliance with the License.  You may obtain a copy of
   the License at

   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
   implied.  See the License for the specific language governing
   permissions and limitations under the License.

.. include:: ../../../common.defs

.. default-domain:: cpp

TSMimeHdrFieldNext
******************

Synopsis
========

.. code-block:: cpp

    #include <ts/ts.h>

.. function:: TSMLoc TSMimeHdrFieldNext(TSMBuffer bufp, TSMLoc hdr, TSMLoc field)

Description
===========

Returns the location of the MIME field that follows :arg:`field` in the MIME header located at :arg:`hdr` within
:arg:`bufp`, or :var:`TS_NULL_MLOC` if :arg:`field` is the last one. If :arg:`field` has been destroyed with
:func:`TSMimeHdrFieldDestroy`, this is the field that followed it, so a loop can destroy the current field and continue.

Release the returned :cpp:type:`TSMLoc` with :func:`TSHandleMLocRelease`.
