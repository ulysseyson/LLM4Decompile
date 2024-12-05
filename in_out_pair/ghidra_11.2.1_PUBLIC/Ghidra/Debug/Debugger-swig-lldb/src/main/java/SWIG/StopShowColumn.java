/* ###
 * IP: Apache License 2.0 with LLVM Exceptions
 */
/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (https://www.swig.org).
 * Version 4.1.1
 *
 * Do not make changes to this file unless you know what you are doing - modify
 * the SWIG interface file instead.
 * ----------------------------------------------------------------------------- */

package SWIG;

public final class StopShowColumn {
  public final static StopShowColumn eStopShowColumnAnsiOrCaret = new StopShowColumn("eStopShowColumnAnsiOrCaret", lldbJNI.eStopShowColumnAnsiOrCaret_get());
  public final static StopShowColumn eStopShowColumnAnsi = new StopShowColumn("eStopShowColumnAnsi", lldbJNI.eStopShowColumnAnsi_get());
  public final static StopShowColumn eStopShowColumnCaret = new StopShowColumn("eStopShowColumnCaret", lldbJNI.eStopShowColumnCaret_get());
  public final static StopShowColumn eStopShowColumnNone = new StopShowColumn("eStopShowColumnNone", lldbJNI.eStopShowColumnNone_get());

  public final int swigValue() {
    return swigValue;
  }

  public String toString() {
    return swigName;
  }

  public static StopShowColumn swigToEnum(int swigValue) {
    if (swigValue < swigValues.length && swigValue >= 0 && swigValues[swigValue].swigValue == swigValue)
      return swigValues[swigValue];
    for (int i = 0; i < swigValues.length; i++)
      if (swigValues[i].swigValue == swigValue)
        return swigValues[i];
    throw new IllegalArgumentException("No enum " + StopShowColumn.class + " with value " + swigValue);
  }

  private StopShowColumn(String swigName) {
    this.swigName = swigName;
    this.swigValue = swigNext++;
  }

  private StopShowColumn(String swigName, int swigValue) {
    this.swigName = swigName;
    this.swigValue = swigValue;
    swigNext = swigValue+1;
  }

  private StopShowColumn(String swigName, StopShowColumn swigEnum) {
    this.swigName = swigName;
    this.swigValue = swigEnum.swigValue;
    swigNext = this.swigValue+1;
  }

  private static StopShowColumn[] swigValues = { eStopShowColumnAnsiOrCaret, eStopShowColumnAnsi, eStopShowColumnCaret, eStopShowColumnNone };
  private static int swigNext = 0;
  private final int swigValue;
  private final String swigName;
}

